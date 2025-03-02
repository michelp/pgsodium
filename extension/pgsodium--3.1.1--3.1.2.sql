DROP EVENT TRIGGER  pgsodium_trg_mask_update;

CREATE EVENT TRIGGER pgsodium_trg_mask_update
  ON ddl_command_end
  WHEN TAG IN (
    'SECURITY LABEL',
    'ALTER TABLE'
  )
  EXECUTE PROCEDURE pgsodium.trg_mask_update()
;
