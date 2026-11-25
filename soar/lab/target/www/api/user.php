<?php
// Vulnerabilite volontaire : IDOR / BOLA (aucun controle d'acces sur l'identifiant).
header("Content-Type: application/json");
$id = intval($_GET["id"] ?? 0);
if ($id < 1 || $id > 50) { http_response_code(404); echo '{"erreur":"inconnu"}'; exit; }
echo json_encode(["id" => $id, "login" => "client$id", "email" => "client$id@boutique-labo.invalid", "solde" => $id * 13]);
