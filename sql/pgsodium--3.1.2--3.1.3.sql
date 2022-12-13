
CREATE OR REPLACE FUNCTION pgsodium.trg_mask_update()
RETURNS EVENT_TRIGGER AS
$$
DECLARE
  r record;
BEGIN
  IF (select bool_or(in_extension) FROM pg_event_trigger_ddl_commands()) THEN
    RAISE NOTICE 'skipping pgsodium mask regeneration in extension';
	RETURN;
  END IF;
  PERFORM @extschema@.update_masks();
END
$$
  LANGUAGE plpgsql
  SET search_path=''
;
	
