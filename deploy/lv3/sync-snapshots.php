<?php
require '/var/www/html/vendor/autoload.php';
Config::load('/var/www/html/.env');
require __DIR__.'/helpers.php';
umask(0077);$lock=fopen(__DIR__.'/snapshot-sync.lock','c');if(!flock($lock,LOCK_EX|LOCK_NB))exit(0);
$archive=__DIR__.'/snapshots.tar.gz';
try {
migrationTransfer(migrationSsh(27),'tar -C /var/lib/infodash/projects -czf - .',$archive,true,30);
migrationTransfer(migrationSsh(31),'umask 077; cat > /root/info-ru2-migration/snapshots.tar.gz; python3 /root/info-ru2-migration/install-snapshots.py',$archive,false,30);
} catch (Throwable $e) {
 fwrite(STDERR, 'Info snapshot sync failed: '.get_class($e).': '.substr($e->getMessage(),0,400).PHP_EOL);
 exit(1);
}
echo 'Info project snapshots synchronized'.PHP_EOL;