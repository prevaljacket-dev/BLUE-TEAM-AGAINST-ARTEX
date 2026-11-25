<?php
// Vulnerabilite volontaire : mot de passe faible, aucune limite de tentatives.
require "_layout.php";
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (($_POST["user"] ?? "") === "admin" && ($_POST["pass"] ?? "") === "admin123") {
        page_top("Espace admin"); echo "<p>Bienvenue admin.</p>"; exit;
    }
    http_response_code(401);
}
page_top("Connexion");
if ($_SERVER["REQUEST_METHOD"] === "POST") echo "<p>Identifiants invalides.</p>";
?>
<form method=post><input name=user placeholder=utilisateur> <input name=pass type=password placeholder="mot de passe"> <button>Entrer</button></form>
