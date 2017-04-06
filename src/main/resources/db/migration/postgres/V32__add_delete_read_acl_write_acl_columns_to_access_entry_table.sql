ALTER TABLE access_entry
  ADD COLUMN delete_permission BOOL DEFAULT FALSE NOT NULL;

ALTER TABLE access_entry
  ADD COLUMN read_acl_permission BOOL DEFAULT FALSE NOT NULL;

ALTER TABLE access_entry
  ADD COLUMN write_acl_permission BOOL DEFAULT FALSE NOT NULL;

ALTER TABLE access_entry
  ALTER COLUMN read_permission SET NOT NULL;

ALTER TABLE access_entry
  ALTER COLUMN write_permission SET NOT NULL;
