<?php
// Vulnerabilite volontaire : XSS refletee.
require "_layout.php"; page_top("Recherche");
$q = $_GET["q"] ?? "";
echo "<form><input name=q value=\"$q\"><button>Chercher</button></form>";
echo "<p>Resultats pour : $q</p><p>Aucun produit.</p>";
