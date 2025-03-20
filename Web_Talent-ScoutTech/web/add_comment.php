<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Require logged users
require dirname(__FILE__) . '/private/auth.php';

if (isset($_POST['body']) && isset($_GET['id'])) {
    // Validar que $_GET['id'] es un número entero
    if (!filter_var($_GET['id'], FILTER_VALIDATE_INT)) {
        die("Invalid player ID");
    }

    // Validar que $_COOKIE['userId'] es un número entero
    if (!isset($_COOKIE['userId']) || !filter_var($_COOKIE['userId'], FILTER_VALIDATE_INT)) {
        die("Invalid user ID");
    }

    // Obtener y sanitizar las entradas
    $body = $_POST['body'];
    $playerId = intval($_GET['id']);
    $userId = intval($_COOKIE['userId']);

    // Preparar la consulta con parámetros
    $stmt = $db->prepare("INSERT INTO comments (playerId, userId, body) VALUES (?, ?, ?)");
    $stmt->bindValue(1, $playerId, SQLITE3_INTEGER);
    $stmt->bindValue(2, $userId, SQLITE3_INTEGER);
    $stmt->bindValue(3, $body, SQLITE3_TEXT);

    // Ejecutar la consulta y verificar errores
    if (!$stmt->execute()) {
        die("Error: Could not insert comment");
    }

    // Redirigir al usuario
    header("Location: list_players.php");
    exit();
}

# Show form
?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Comments creator</title>
</head>
<body>
<header>
    <h1>Comments creator</h1>
</header>
<main class="player">
    <form action="#" method="post">
        <h3>Write your comment</h3>
        <textarea name="body"></textarea>
        <input type="submit" value="Send">
    </form>
    <form action="#" method="post" class="menu-form">
        <a href="list_players.php">Back to list</a>
        <input type="submit" name="Logout" value="Logout" class="logout">
    </form>
</main>
<footer class="listado">
    <img src="images/logo-iesra-cadiz-color-blanco.png">
    <h4>Puesta en producción segura</h4>
    < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
</footer>
</body>
</html>

