<?php
// Vulnerabilite volontaire : injection SQL (SQLite en memoire, rien de reel).
require "_layout.php"; page_top("Produit");
$db = new PDO("sqlite::memory:");
$db->exec("CREATE TABLE products(id INTEGER, name TEXT, price REAL); CREATE TABLE users(id INTEGER, login TEXT, password TEXT);");
$db->exec("INSERT INTO products VALUES (1,'Basket Nuage',59.9),(2,'Botte Pluie',79.0),(3,'Sandale Sable',29.5);");
$db->exec("INSERT INTO users VALUES (1,'admin','admin123'),(2,'alice','soleil2026');");
$id = $_GET["id"] ?? "1";
$res = @$db->query("SELECT name, price FROM products WHERE id = $id");
if (!$res) { http_response_code(500); echo "<pre>Erreur SQL : " . htmlspecialchars($db->errorInfo()[2]) . "</pre>"; exit; }
foreach ($res as $row) { echo "<p>{$row[0]} - {$row[1]} EUR</p>"; }
