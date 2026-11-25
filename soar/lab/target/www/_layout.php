<?php
function page_top($title) {
    echo "<!doctype html><html lang=fr><meta charset=utf-8><title>$title - Boutique Labo</title>";
    echo "<style>body{font-family:sans-serif;max-width:760px;margin:2em auto;padding:0 1em}"
       . ".warn{background:#b91c1c;color:#fff;padding:.6em 1em;border-radius:6px}nav a{margin-right:1em}</style>";
    echo "<p class=warn>LABO - CIBLE VOLONTAIREMENT VULNERABLE - NE PAS EXPOSER</p>";
    echo "<nav><a href=/>Accueil</a><a href='/view.php?page=pages/contact.php'>Contact</a>"
       . "<a href='/search.php?q=chaussures'>Recherche</a><a href='/product.php?id=1'>Produit</a>"
       . "<a href=/login.php>Connexion</a><a href='/api/user.php?id=1'>API</a></nav><h1>$title</h1>";
}
