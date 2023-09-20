
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

  FOR r IN
    SELECT e.*
    FROM pg_event_trigger_ddl_commands() e
    WHERE EXISTS (
      SELECT FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_seclabel s ON s.classoid = c.tableoid
                                   AND s.objoid = c.oid
      WHERE c.tableoid = e.classid
        AND e.objid = c.oid
        AND s.provider = 'pgsodium'
    )
  LOOP
    IF r.object_type in ('table', 'table column')
    THEN
      PERFORM pgsodium.update_mask(r.objid);
    END IF;
  END LOOP;
END
$$
  LANGUAGE plpgsql
  SET search_path=''
;
