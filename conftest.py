# Intentionally empty.
#
# Its only job is to exist at the project root: pytest's default
# ("prepend") import mode inserts the directory containing each
# conftest.py onto sys.path during collection, which is what lets
# tests/test_storage.py do `import storage.encryption` etc. without any
# packaging/setup.py or manual sys.path hacks in the test file itself.
