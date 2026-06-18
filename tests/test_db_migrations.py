from graphpt.db.migrations import _MIGRATIONS, schema_version_latest


def test_migration_versions_are_unique_and_increasing():
    versions = [version for version, _desc, _sqls in _MIGRATIONS]

    assert versions == sorted(versions)
    assert len(versions) == len(set(versions))
    assert schema_version_latest() >= versions[-1]
