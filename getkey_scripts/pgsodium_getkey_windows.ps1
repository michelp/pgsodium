$KEY_FILE = "$PGDATA/pgsodium_root.key"

if (-not(Test-Path -Path $KEY_FILE -PathType Leaf))
{
  (1..64|foreach-object {'{0:x}' -f (Get-Random -Maximum 16)}) -join '' > $KEY_FILE
}
cat $KEY_FILE