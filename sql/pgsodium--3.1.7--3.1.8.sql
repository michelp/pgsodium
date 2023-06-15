
CREATE OR REPLACE FUNCTION pgsodium.trg_mask_update()
RETURNS EVENT_TRIGGER AS
$$
DECLARE
  r record;
BEGIN
  IF (SELECT bool_or(in_extension) FROM pg_event_trigger_ddl_commands()) THEN
    RAISE NOTICE 'skipping pgsodium mask regeneration in extension';
	RETURN;
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM pg_event_trigger_ddl_commands() c, pg_seclabel s
      WHERE c.classid = s.classoid
      AND c.objid = s.objoid
      -- AND c.objsubid = s.objsubid -- tce may depend on other columns
      AND s.provider = 'pgsodium'
    ) THEN
	RETURN;
  END IF;
  PERFORM @extschema@.update_masks();
END
$$
  LANGUAGE plpgsql
  SET search_path=''
;
