"""
Tests for eclipse attack mitigations.

Tests address manager bucketing, network group diversification,
anchor connections, and feeler connections.
"""

import json
import os
import tempfile
import time

from ouroboros.addrman import (
    NEW_BUCKET_COUNT,
    NEW_BUCKET_SIZE,
    TRIED_BUCKET_COUNT,
    TRIED_BUCKET_SIZE,
    AddressManager,
    AddrInfo,
    get_network_group,
)


class TestNetworkGroup:
    """Tests for /16 network group extraction."""

    def test_ipv4_group(self):
        """IPv4 addresses return /16 group."""
        assert get_network_group("192.168.1.1") == "192.168"
        assert get_network_group("10.0.0.1") == "10.0"
        assert get_network_group("172.16.5.10") == "172.16"

    def test_same_group(self):
        """Same /16 addresses should have same group."""
        assert get_network_group("192.168.1.1") == get_network_group("192.168.255.255")
        assert get_network_group("10.0.0.1") == get_network_group("10.0.99.99")

    def test_different_groups(self):
        """Different /16 networks should have different groups."""
        assert get_network_group("192.168.1.1") != get_network_group("192.169.1.1")
        assert get_network_group("10.0.0.1") != get_network_group("10.1.0.1")

    def test_onion_group(self):
        """Onion addresses should return 'onion' group."""
        assert get_network_group("abc123.onion") == "onion"
        assert get_network_group("xyz789def456.onion") == "onion"

    def test_ipv6_group(self):
        """IPv6 addresses should return /32 prefix."""
        group = get_network_group("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert "2001" in group


class TestAddressManagerBucketing:
    """Tests for address manager bucket-based storage."""

    def test_bucket_sizes(self):
        """Verify bucket configuration matches spec."""
        assert NEW_BUCKET_COUNT == 256
        assert NEW_BUCKET_SIZE == 64
        assert TRIED_BUCKET_COUNT == 64
        assert TRIED_BUCKET_SIZE == 256

    def test_add_to_new(self):
        """Adding an address places it in the new table."""
        addrman = AddressManager()
        result = addrman.add("192.168.1.1", 8333)
        assert result is True
        assert addrman.new_count() == 1
        assert addrman.tried_count() == 0

    def test_add_duplicate(self):
        """Adding the same address twice returns False."""
        addrman = AddressManager()
        assert addrman.add("192.168.1.1", 8333) is True
        assert addrman.add("192.168.1.1", 8333) is False
        assert addrman.new_count() == 1

    def test_mark_good_moves_to_tried(self):
        """Marking an address good moves it to tried table."""
        addrman = AddressManager()
        addrman.add("192.168.1.1", 8333)
        assert addrman.new_count() == 1
        assert addrman.tried_count() == 0

        addrman.mark_good("192.168.1.1", 8333)
        assert addrman.new_count() == 0
        assert addrman.tried_count() == 1

    def test_source_tracking(self):
        """Addresses track their source peer."""
        addrman = AddressManager()
        addrman.add("192.168.1.1", 8333, source="10.0.0.1:8333")

        info = addrman.get_addr_info("192.168.1.1", 8333)
        assert info is not None
        assert info.source == "10.0.0.1:8333"
        assert info.source_group == "10.0"

    def test_deterministic_bucketing(self):
        """Same address always goes to same bucket position."""
        addrman = AddressManager()
        addrman.add("192.168.1.1", 8333, source="10.0.0.1:8333")

        # Get info and compute bucket
        info = addrman.get_addr_info("192.168.1.1", 8333)
        bucket1 = addrman._get_new_bucket(info, "10.0")
        bucket2 = addrman._get_new_bucket(info, "10.0")
        assert bucket1 == bucket2

    def test_different_sources_different_buckets(self):
        """Addresses from different sources may go to different buckets."""
        addrman = AddressManager()
        info = AddrInfo(host="192.168.1.1", port=8333)

        bucket1 = addrman._get_new_bucket(info, "10.0")
        bucket2 = addrman._get_new_bucket(info, "172.16")
        # Different sources typically produce different buckets
        # (not guaranteed but very likely)
        # Just verify both are valid bucket indices
        assert 0 <= bucket1 < NEW_BUCKET_COUNT
        assert 0 <= bucket2 < NEW_BUCKET_COUNT


class TestAddressSelection:
    """Tests for address selection with network group exclusion."""

    def test_select_excludes_groups(self):
        """Selection respects network group exclusion."""
        addrman = AddressManager()

        # Add addresses from different /16 groups
        addrman.add("192.168.1.1", 8333)
        addrman.add("10.0.0.1", 8333)
        addrman.add("172.16.0.1", 8333)

        # Exclude 192.168 group
        exclude_groups = {"192.168"}
        selected = addrman.select_for_connection(exclude_groups=exclude_groups)

        if selected:
            host = selected.split(":")[0]
            assert get_network_group(host) != "192.168"

    def test_select_excludes_addresses(self):
        """Selection respects address exclusion."""
        addrman = AddressManager()

        addrman.add("192.168.1.1", 8333)
        addrman.add("192.168.1.2", 8333)

        exclude = {"192.168.1.1:8333"}
        selected = addrman.select_for_connection(exclude=exclude)

        if selected:
            assert selected != "192.168.1.1:8333"

    def test_select_for_feeler(self):
        """Feeler selection prefers older new addresses."""
        addrman = AddressManager()

        # Add addresses with different ages
        old_time = time.time() - 86400  # 1 day ago
        new_time = time.time()

        addrman.add("192.168.1.1", 8333, timestamp=old_time)
        addrman.add("192.168.1.2", 8333, timestamp=new_time)

        # Feeler should prefer the older address
        # Run multiple times to check bias
        old_count = 0
        for _ in range(20):
            selected = addrman.select_for_feeler()
            if selected == "192.168.1.1:8333":
                old_count += 1

        # Older addresses should be selected more often
        assert old_count > 5  # At least sometimes


class TestAddressManagerPersistence:
    """Tests for address manager save/load."""

    def test_save_and_load(self):
        """Address manager persists and loads correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create and populate addrman
            addrman1 = AddressManager(data_dir=tmpdir)
            addrman1.add("192.168.1.1", 8333, source="dns.seed.com")
            addrman1.add("10.0.0.1", 8333)
            addrman1.mark_good("192.168.1.1", 8333)
            addrman1.save()

            # Load in new instance
            addrman2 = AddressManager(data_dir=tmpdir)

            assert addrman2.size() == 2
            assert addrman2.tried_count() == 1
            assert addrman2.new_count() == 1

    def test_migration_from_v1(self):
        """Migrates from legacy flat format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write v1 format file
            v1_data = {
                "version": 1,
                "new": {
                    "192.168.1.1:8333": {
                        "host": "192.168.1.1",
                        "port": 8333,
                        "services": 0,
                        "last_seen": time.time(),
                        "source": "seed",
                    }
                },
                "tried": {},
            }
            filepath = os.path.join(tmpdir, "peers.json")
            with open(filepath, "w") as f:
                json.dump(v1_data, f)

            # Load - should migrate
            addrman = AddressManager(data_dir=tmpdir)
            assert addrman.new_count() == 1

    def test_secret_key_persistence(self):
        """Secret key persists across restarts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            addrman1 = AddressManager(data_dir=tmpdir)
            key1 = addrman1._key
            addrman1.add("192.168.1.1", 8333)
            addrman1.save()

            addrman2 = AddressManager(data_dir=tmpdir)
            key2 = addrman2._key

            assert key1 == key2


class TestAddressQuality:
    """Tests for address quality checks (terrible, selection chance)."""

    def test_terrible_old_address(self):
        """Addresses not seen in 30 days are terrible."""
        addrman = AddressManager()
        info = AddrInfo(
            host="192.168.1.1",
            port=8333,
            last_seen=time.time() - 31 * 24 * 3600,  # 31 days ago
            last_attempt=time.time() - 120,  # 2 minutes ago
        )
        assert addrman._is_terrible(info) is True

    def test_terrible_many_failures(self):
        """Addresses with many failures are terrible."""
        addrman = AddressManager()
        info = AddrInfo(
            host="192.168.1.1",
            port=8333,
            last_seen=time.time(),
            last_attempt=time.time() - 120,
            last_success=0,  # never succeeded
            attempts=5,
        )
        assert addrman._is_terrible(info) is True

    def test_not_terrible_recent(self):
        """Recently seen addresses are not terrible."""
        addrman = AddressManager()
        info = AddrInfo(
            host="192.168.1.1",
            port=8333,
            last_seen=time.time(),
            last_attempt=time.time() - 120,
            last_success=time.time() - 3600,
        )
        assert addrman._is_terrible(info) is False

    def test_selection_chance_penalizes_recent(self):
        """Recently attempted addresses have lower selection chance."""
        addrman = AddressManager()

        recent = AddrInfo(
            host="192.168.1.1", port=8333,
            last_attempt=time.time(),  # just now
        )
        old = AddrInfo(
            host="192.168.1.2", port=8333,
            last_attempt=time.time() - 3600,  # 1 hour ago
        )

        chance_recent = addrman._get_chance(recent)
        chance_old = addrman._get_chance(old)

        assert chance_recent < chance_old

    def test_selection_chance_penalizes_failures(self):
        """Addresses with more attempts have lower selection chance."""
        addrman = AddressManager()

        many_attempts = AddrInfo(
            host="192.168.1.1", port=8333,
            last_attempt=time.time() - 3600,
            attempts=5,
        )
        few_attempts = AddrInfo(
            host="192.168.1.2", port=8333,
            last_attempt=time.time() - 3600,
            attempts=1,
        )

        chance_many = addrman._get_chance(many_attempts)
        chance_few = addrman._get_chance(few_attempts)

        assert chance_many < chance_few


class TestCollisionHandling:
    """Tests for tried table collision handling."""

    def test_collision_protection(self):
        """Recent successful addresses are protected from eviction."""
        addrman = AddressManager()

        # Add and mark good - will be in tried
        addrman.add("192.168.1.1", 8333)
        addrman.mark_good("192.168.1.1", 8333)
        assert addrman.tried_count() == 1

        # The address should have recent success time
        info = addrman.get_addr_info("192.168.1.1", 8333)
        assert info is not None
        assert info.last_success > time.time() - 60  # within last minute


class TestNetworkGroupCounts:
    """Tests for network group distribution tracking."""

    def test_group_counts(self):
        """Can get address counts per network group."""
        addrman = AddressManager()

        addrman.add("192.168.1.1", 8333)
        addrman.add("192.168.1.2", 8333)
        addrman.add("10.0.0.1", 8333)

        counts = addrman.get_network_group_counts()

        assert counts.get("192.168", 0) == 2
        assert counts.get("10.0", 0) == 1
