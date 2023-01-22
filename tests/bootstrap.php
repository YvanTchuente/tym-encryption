<?php

require dirname(__DIR__) . '/vendor/autoload.php';

$loader = new \Composer\Autoload\ClassLoader();
$loader->addPsr4("Tym\\Encryption\\", dirname(__DIR__) . "/src");
$loader->register();
