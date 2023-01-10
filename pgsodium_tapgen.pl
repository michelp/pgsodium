#!/usr/bin/perl -w

use strict;
use warnings;
use DBI;
use DBD::Pg;
use Getopt::Long;
use File::Spec;

my $PGSODIUM_VERSION = '3.1.5';
my $rs;

Getopt::Long::Configure (qw(bundling));

my $opts = { psql => 'psql', create_extension => 1 };

Getopt::Long::GetOptions(
    'dbname|d=s'          => \$opts->{dbname},
    'username|U=s'        => \$opts->{username},
    'host|h=s'            => \$opts->{host},
    'port|p=s'            => \$opts->{port},
    'exclude-schema|N=s@' => \$opts->{exclude_schema},
    'create-extension|c!' => \$opts->{create_extension},
) or require Pod::Usage && Pod::Usage::pod2usage(2);

my @conn;
for (qw(host port dbname)) {
    push @conn, "$_=$opts->{$_}" if defined $opts->{$_};
}
my $dsn = 'dbi:Pg:';
$dsn .= join ';', @conn if @conn;

my $dbh = DBI->connect($dsn, $opts->{username}, $ENV{PGPASSWORD}, {
    RaiseError     => 1,
    PrintError     => 0,
    AutoCommit     => 1,
    pg_enable_utf8 => 1,
});
$dbh->do(q{SET client_encoding = 'UTF-8'});
$dbh->begin_work;
#$dbh->do(q{BEGIN});
$dbh->do(q{CREATE EXTENSION pgsodium});

################################################################################

print "BEGIN;\n",
      "CREATE EXTENSION IF NOT EXISTS pgtap;\n",
      "CREATE EXTENSION IF NOT EXISTS pgsodium;\n\n",
      "SET search_path TO 'public';\n\n";

print "SELECT no_plan();\n";

print "\n\n\n---- EXTENSION VERSION\n";

printf q{SELECT results_eq('SELECT pgsodium.version()', }
      .q{$$VALUES ('%s'::text)$$, }
      .q{'Version of pgsodium is %1$s');},
    $PGSODIUM_VERSION;

# check all objects installed by the extension. No more no less.
print "\n\n\n---- EXTENSION OBJECTS\n";
print "-- Note: pay close attention to the objects schema when applicable,\n",
      "-- it MUST be pgsodium.\n\n";

$rs = $dbh->selectcol_arrayref(q{
    SELECT format('(%-110L::text)', pg_catalog.pg_describe_object(classid, objid, 0))
    FROM pg_catalog.pg_depend
    WHERE refclassid = 'pg_catalog.pg_extension'::pg_catalog.regclass
      AND refobjid = (SELECT oid FROM pg_extension WHERE extname = 'pgsodium')
      AND deptype = 'e'
    ORDER BY 1;
}) or die;

print q{SELECT results_eq($$
  SELECT pg_catalog.pg_describe_object(classid, objid, 0)
  FROM pg_catalog.pg_depend
  WHERE refclassid = 'pg_catalog.pg_extension'::pg_catalog.regclass
    AND refobjid = (SELECT oid FROM pg_extension WHERE extname = 'pgsodium')
    AND deptype = 'e'
  ORDER BY 1$$,
  $$ VALUES
    }, join(",\n    ", @$rs), q{
  $$,
  'Check extension object list');
};


print "\n\n\n---- ROLES\n\n";
$rs = $dbh->selectcol_arrayref(q{
    SELECT quote_literal(rolname)
      FROM pg_catalog.pg_roles
     WHERE rolname LIKE 'pgsodium%'
     ORDER BY rolname
}) or die;

foreach my $r (@$rs) {
    print "SELECT has_role($r);\n";
}

$rs = $dbh->selectall_arrayref(q{
SELECT quote_literal(m.roleid::regrole), quote_literal(r.rolname)
FROM pg_catalog.pg_roles r
JOIN pg_catalog.pg_auth_members m
  ON r.oid = m.member
WHERE rolname LIKE 'pgsodium%'
ORDER BY rolname
}) or die;

foreach my $r (@$rs) {
    printf "SELECT is_member_of( %s, %s );\n", $r->[0], $r->[1];
}

# TODO: granted roles to roles

$rs = $dbh->selectall_arrayref(q{
    SELECT quote_literal(nspname),
      quote_literal(pg_catalog.pg_get_userbyid(nspowner))
    FROM pg_catalog.pg_namespace
    WHERE nspname NOT IN ('pg_catalog', 'pg_toast', 'information_schema')
    ORDER BY nspname
}) or die;

print "\n\n\n---- SCHEMAS\n\n";

print "SELECT schemas_are(ARRAY[\n    ",
      join(",\n    ", map {$_->[0]} @$rs),
      "\n]);\n";

foreach my $r ( @$rs ) {
    printf "SELECT schema_owner_is(%-10s, %s);\n", @$r;
}

print "\n\n\n---- TABLES\n\n";

$rs = get_rels('r', 'pgsodium');

print "SELECT tables_are('pgsodium', ARRAY[\n    ",
    join(",\n    ", map {$_->[0]} @$rs),
    "\n]);\n\n";

for my $r (@$rs) {
    my $tname  = $r->[2];
    my $qtname = $r->[0];
    print "---- TABLE $tname\n";

    # COLUMNS
    cols_tests('pgsodium', $tname);

    # PK
    if ( hasc('pgsodium', $tname, 'p')) {
        printf "SELECT has_pk('pgsodium', %s, 'table %s has a PK');\n", $qtname, $tname;
    }
    else {
        printf "SELECT hasnt_pk('pgsodium', %s, 'table %s has no PK');\n", $qtname, $tname;
    }

    # TRIGGERS
    trgs_tests('pgsodium', $tname);

    # OWNER
    print "\n-- owner of table $tname\n";
    printf "SELECT table_owner_is('pgsodium'::name, %s::name, %s::name);\n", @$r[0..1];

    # PRIVILEGES
    privs_tests('pgsodium', $tname);
}

print "\n\n\n---- VIEWS\n\n";

$rs = get_rels('v', 'pgsodium');

print "SELECT views_are('pgsodium', ARRAY[\n    ",
    join(",\n    ", map {$_->[0]} @$rs),
    "\n]);\n\n";

for my $r (@$rs) {
    my $tname  = $r->[2];
    my $qtname = $r->[0];
    print "---- VIEW $tname\n";

    # COLUMNS
    cols_tests('pgsodium', $tname);

    # TRIGGERS
    trgs_tests('pgsodium', $tname);

    # OWNER
    print "\n-- owner of view $tname\n";
    printf "SELECT view_owner_is('pgsodium'::name, %s::name, %s::name);\n", @$r[0..1];

    # PRIVILEGES
    privs_tests('pgsodium', $tname);
}

print "\n\n\n---- SEQUENCES\n\n";

$rs = get_rels('S', 'pgsodium');

print "SELECT sequences_are('pgsodium', ARRAY[\n    ",
    join(",\n    ", map {$_->[0]} @$rs),
    "\n]);\n\n";

for my $r (@$rs) {
    my $tname  = $r->[2];
    my $qtname = $r->[0];
    print "---- SEQUENCE $tname\n";

    # OWNER
    print "\n-- owner of sequence $tname\n";
    printf "SELECT sequence_owner_is('pgsodium'::name, %s::name, %s::name);\n", @$r[0..1];

    # PRIVILEGES
    privs_tests('pgsodium', $tname, 'sequence');
}

print "\n\n\n---- FUNCTIONS\n\n";

my $allfuncs = $dbh->selectall_arrayref(q{
    SELECT p.proname, md5(p.prosrc) as md5,
      oidvectortypes(proargtypes) as proargs, proowner::regrole
    FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON p.pronamespace = n.oid
    WHERE n.nspname = 'pgsodium'
    ORDER BY p.proname, proargs
}, undef);

my @funcs = do {
    my %seen;
    grep { !$seen{$_}++ } map { $_->[0] } @$allfuncs;
};

print "SELECT functions_are('pgsodium', ARRAY[\n    '",
    join("',\n    '", @funcs),
    "'\n]);\n\n";

for my $row (@$allfuncs) {
    my ($proname, $md5, $proargs, $owner) = @$row;
    my $allprivs = $dbh->selectall_arrayref(q{
          SELECT quote_literal(p.proowner::regrole), quote_literal(g.rolname),
          array_agg(p.privilege_type::text ORDER BY privilege_type)::text,
          quote_literal(p.proname)
      FROM 
        ( SELECT pg_proc.oid,
                 pg_proc.proname,
                 pg_proc.proowner,
                 pg_proc.proargtypes,
                 (aclexplode(COALESCE(pg_proc.proacl, acldefault('f'::"char", pg_proc.proowner)))).grantee AS grantee,
                 (aclexplode(COALESCE(pg_proc.proacl, acldefault('f'::"char", pg_proc.proowner)))).privilege_type AS privilege_type
          FROM pg_catalog.pg_proc
          JOIN pg_catalog.pg_namespace n ON pg_proc.pronamespace = n.oid
          WHERE n.nspname = 'pgsodium'
            AND pg_proc.proname = ?
            AND oidvectortypes(pg_proc.proargtypes) = ?
        ) p
      JOIN ( SELECT r.oid, r.rolname
             FROM pg_roles r
             UNION ALL
             SELECT 0::oid AS oid, 'public'::name
           ) g(oid, rolname) ON g.oid = p.grantee
      GROUP BY p.proowner, p.proargtypes, g.rolname, p.proname
    }, undef, $proname, $proargs);

    my ($qpowner, $qgrantee, $privs, $qproname) = @{ $allprivs->[0] };

    printf "SELECT unnest(ARRAY[\n"
          ."    is(md5(prosrc), '%s',\n"
          ."       format('Function pgsodium.%%s(%%s) body should match checksum',\n"
          ."              proname, pg_get_function_identity_arguments(oid))\n"
          ."    ),\n"
          ."    function_owner_is(\n"
          ."      'pgsodium'::name, proname,\n"
          ."      proargtypes::regtype[]::name[], %s::name,\n"
          ."      format('Function pgsodium.%%s(%%s) owner is %%s',\n"
          ."             proname, pg_get_function_identity_arguments(oid), %2\$s)\n"
          ."    )\n"
          ."])\n"
          ."  FROM pg_catalog.pg_proc\n"
          ."  WHERE pronamespace = 'pgsodium'::regnamespace\n"
          ."    AND proname = %s\n"
          ."    AND oidvectortypes(proargtypes) = '%s';\n\n",
          $md5, $qpowner, $qproname, $proargs;

    foreach my $p (@{ $allprivs }) {
        ($qpowner, $qgrantee, $privs, $qproname) = @$p;
        printf "SELECT function_privs_are('pgsodium'::name, proname, proargtypes::regtype[]::text[], %s, '%s'::text[])\n"
              ."  FROM pg_catalog.pg_proc\n"
              ."  WHERE pronamespace = 'pgsodium'::regnamespace\n"
              ."    AND proname = %s\n"
              ."    AND oidvectortypes(proargtypes) = '%s';\n\n",
                   $qgrantee, $privs, $qproname, $proargs;
    
    }
}

print "\n\nROLLBACK;\n";

$dbh->rollback;

exit;

################################################################################

sub get_rels {
    my $sth = $dbh->prepare_cached(q{
        SELECT quote_literal(c.relname), quote_literal(pg_catalog.pg_get_userbyid(c.relowner)),
               c.relname, c.oid
          FROM pg_catalog.pg_namespace n
          JOIN pg_catalog.pg_class c ON n.oid = c.relnamespace
         WHERE c.relkind = ?
           AND n.nspname = ?
         ORDER BY c.relname
    });
    return $dbh->selectall_arrayref($sth, undef, @_);
}

sub cols_tests {
    my ($schema, $tname) = @_;
    my $cols = $dbh->selectall_arrayref(q{
        SELECT quote_literal(n.nspname), quote_literal(c.relname)
             , quote_literal(a.attname), a.attname
             , pg_catalog.format_type(a.atttypid, a.atttypmod) AS type
             , a.attnotnull AS not_null
             , a.atthasdef  AS has_default
             , CASE WHEN pg_catalog.pg_get_expr(d.adbin, d.adrelid) LIKE '''%'
                    THEN pg_catalog.pg_get_expr(d.adbin, d.adrelid)
                    ELSE quote_literal(pg_catalog.pg_get_expr(d.adbin, d.adrelid))
               END
          FROM pg_catalog.pg_namespace n
          JOIN pg_catalog.pg_class c ON n.oid = c.relnamespace
          JOIN pg_catalog.pg_attribute a ON c.oid = a.attrelid
          LEFT JOIN pg_catalog.pg_attrdef d ON a.attrelid = d.adrelid AND a.attnum = d.adnum
         WHERE n.nspname = ?
           AND c.relname = ?
           AND a.attnum > 0
           AND NOT a.attisdropped
         ORDER BY a.attnum
    }, undef, $schema, $tname);

    print "\n-- cols of relation $tname\n";
    printf "SELECT columns_are(%s::name, %s::name, ARRAY[\n  "
         . join(",\n  ", map { $_->[2] } @$cols)
         . "\n]::name[]);\n\n", $cols->[0][0], $cols->[0][1];

    for my $col ( @$cols ) {
        my ($qschema, $qtname, $qattname, $attname, $atttyp,
            $attnotnull, $atthasdef, $attdef) = @$col;
        my $null_fn = $attnotnull ? 'col_not_null(' : 'col_is_null(';
        my $def_fn = $atthasdef ? 'col_has_default(' : 'col_hasnt_default(';
        
        printf "SELECT has_column(       %s, %s, %-17s, 'has column %s.%s');\n", $qschema, $qtname, $qattname, $tname, $attname;
        printf "SELECT col_type_is(      %s, %s, %-17s, '%s', 'type of column %s.%s is %4\$s');\n", $qschema, $qtname, $qattname, $atttyp, $tname, $attname;
        printf "SELECT %-18s%s, %s, %-17s, '$null_fn %s.%s )');\n", $null_fn, $qschema, $qtname, $qattname, $tname, $attname;
        printf "SELECT %-18s%s, %s, %-17s, '$def_fn %s.%s )');\n", $def_fn, $qschema, $qtname, $qattname, $tname, $attname;
        printf "SELECT col_default_is(   %s, %s, %-17s, %s, 'default definition of %s.%s');\n", $qschema, $qtname, $qattname, $attdef, $tname, $attname
            if $atthasdef;
        print "\n";
    }
}

sub privs_tests {
    my ($schema, $tname, $type) = @_;
    $type = 'table' unless defined $type;
    my $privs = $dbh->selectall_arrayref(qq{
    SELECT quote_literal(a.rolname), array_agg(s.p)::text,
        quote_literal(r.nspname), quote_literal(r.relname)
      FROM ( SELECT oid, rolname FROM pg_catalog.pg_authid
             UNION ALL
             SELECT 0::oid AS oid, 'public'::name
           ) AS a,
           ( SELECT 'r', unnest(ARRAY[
                           'INSERT', 'SELECT', 'UPDATE', 'DELETE',
                           'TRUNCATE', 'REFERENCES', 'TRIGGER'
                         ])
             UNION ALL
             SELECT 'v', unnest(ARRAY[
                           'INSERT', 'SELECT', 'UPDATE', 'DELETE',
                           'TRUNCATE', 'REFERENCES', 'TRIGGER'
                         ])
             UNION ALL
             SELECT 'S', unnest(ARRAY[
                           'USAGE', 'SELECT', 'UPDATE'
                         ])
           ) AS s(k, p),
           ( SELECT c.oid, n.nspname, c.relname, c.relkind
             FROM pg_catalog.pg_class c
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = ?
               AND c.relname = ?
           ) AS r
     WHERE CASE WHEN r.relkind = 'r' THEN has_table_privilege(a.oid, r.oid, s.p)
                WHEN r.relkind = 'v' THEN has_table_privilege(a.oid, r.oid, s.p)
                WHEN r.relkind = 'S' THEN has_sequence_privilege(a.oid, r.oid, s.p)
           END
       AND s.k = r.relkind
     GROUP BY a.rolname, r.nspname, r.relname
     ORDER BY a.rolname}, undef, $schema, $tname);

    print "\n\n-- privs of relation $tname\n";
    foreach my $p ( @$privs ) {
        printf
            "SELECT %s_privs_are(%s::name, %s::name, %-28s::name, '%s'::text[]);\n",
            $type, $p->[2], $p->[3], $p->[0], $p->[1];
    }

    printf "SELECT %s_privs_are(%s::name, %s::name, rolname,                    '{}'::text[])\n"
          ."FROM pg_catalog.pg_roles\n"
          ."WHERE rolname NOT IN (%s);\n",
          $type, $privs->[0][2], $privs->[0][3],
          join(',',  map { $_->[0] } @$privs);
}

sub trgs_tests {
    my ($schema, $tname) = @_;
    my $tgs = $dbh->selectall_arrayref(q{
    SELECT quote_literal(t.tgname), quote_literal(ni.nspname),
        quote_literal(p.proname), quote_literal(nt.nspname),
        quote_literal(ct.relname)
      FROM pg_catalog.pg_trigger t
      JOIN pg_catalog.pg_class ct     ON ct.oid = t.tgrelid
      JOIN pg_catalog.pg_namespace nt ON nt.oid = ct.relnamespace
      JOIN pg_catalog.pg_proc p       ON p.oid  = t.tgfoid
      JOIN pg_catalog.pg_namespace ni ON ni.oid = p.pronamespace
     WHERE nt.nspname = ?
       AND ct.relname = ?
       AND NOT t.tgisinternal
     ORDER BY t.tgname, ni.nspname, p.proname
    }, undef, $schema, $tname);

    return unless @$tgs;

    print "\n-- triggers of relation $tname\n";
    printf "SELECT triggers_are(%s, %s, ARRAY[\n    "
        .join(",\n    ", map { $_->[0] } @{ $tgs })
        ."\n]);\n\n", $tgs->[0][3], $tgs->[0][4];

    for my $t (@$tgs) {
        my ($tgname, $pronspname, $proname, $nspname, $relname) = @$t;
        printf "SELECT has_trigger( %s, %s, %s::name);\n"
              ."SELECT trigger_is(  %1\$s, %2\$s, %3\$s::name, %s, %s);\n",
              $nspname, $relname, $tgname, $pronspname, $proname;
    }
}

sub hasc {
    return $dbh->selectcol_arrayref(q{
        SELECT EXISTS(
            SELECT true
              FROM pg_catalog.pg_namespace n
              JOIN pg_catalog.pg_class c      ON c.relnamespace = n.oid
              JOIN pg_catalog.pg_constraint x ON c.oid = x.conrelid
              JOIN pg_catalog.pg_index i      ON c.oid = i.indrelid
             WHERE i.indisprimary = true
               AND n.nspname = ?
               AND c.relname = ?
               AND x.contype = ?
        )
    }, undef, @_)->[0];
}
