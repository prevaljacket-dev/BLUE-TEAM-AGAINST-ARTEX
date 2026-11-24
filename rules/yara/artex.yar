/*
  ARTEX blue team - regles YARA
  Usage : yara -r artex.yar /var/lib/php/sessions /tmp /var/www
*/

rule ARTEX_PHP_Session_File_Poisoned
{
    meta:
        description = "Fichier de session PHP contenant du code PHP (chaine php2shell : session.upload_progress + LFI)"
        mitre = "T1190, T1059.004"
        severity = "critical"
    strings:
        $prog1 = "upload_progress_" ascii
        $prog2 = "\"bytes_processed\"" ascii
        $php1  = "<?php" ascii nocase
        $php2  = "<?=" ascii
        $fn1   = "system(" ascii nocase
        $fn2   = "passthru(" ascii nocase
        $fn3   = "shell_exec(" ascii nocase
        $fn4   = "eval(" ascii nocase
        $fn5   = "file_put_contents(" ascii nocase
        $ser   = /^[A-Za-z0-9_]{1,64}\|[aisbdNO]:/
    condition:
        filesize < 2MB and
        ( $ser at 0 or 1 of ($prog*) ) and
        1 of ($php*) and
        ( 1 of ($fn*) or 1 of ($prog*) )
}

rule ARTEX_PHP_Webshell_Generic
{
    meta:
        description = "Webshell PHP minimal typique d'une verification RCE (marqueur echo ou execution de parametre)"
        mitre = "T1505.003"
        severity = "high"
    strings:
        $a1 = /\b(system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/ nocase
        $a2 = /\beval\s*\(\s*(base64_decode|gzinflate|str_rot13)?\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $a3 = /\bassert\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $a4 = /`\s*\$_(GET|POST|REQUEST)\s*\[/
    condition:
        filesize < 512KB and any of them
}

rule ARTEX_Server_Binary_Or_Config
{
    meta:
        description = "Binaire, image ou configuration d'une instance ARTEX (plateforme de pentest autonome)"
        severity = "medium"
        note = "Legitime si deploye par votre equipe offensive autorisee ; sinon a traiter comme outil d'attaque"
    strings:
        $s1 = "ARTEX-Assessment/1.0" ascii
        $s2 = "artex-update-check" ascii
        $s3 = "X-ARTEX-Replay-Nonce" ascii
        $s4 = "ARTEX_NOISE_PROFILE" ascii
        $s5 = "ARTEX_TASK_BUDGET_TOKENS" ascii
        $s6 = "github.com/Autumn-27/artex" ascii
        $s7 = "ARTEX_PG_DBNAME" ascii
        $s8 = "ARTEX_JWT_KEY_DIR" ascii
    condition:
        2 of them
}
