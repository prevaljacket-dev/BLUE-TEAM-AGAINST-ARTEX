<?php
// Vulnerabilite volontaire : inclusion de fichier local (LFI), exploitable en RCE (php2shell).
session_start();
require "_layout.php"; page_top("Pages");
include($_GET["page"] ?? "pages/accueil.php");
