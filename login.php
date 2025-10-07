<?php
session_start();

/**
 * Conexión a BD
 */
function conectarBD()
{
    $host = "localhost";
    $dbuser = "root";
    $dbpass = "";
    $dbname = "usuario_php";
    $conn = new mysqli($host, $dbuser, $dbpass, $dbname);

    if ($conn->connect_error) {
        die("Conexión fallida: " . $conn->connect_error);
    }
    return $conn;
}

// --- LOGIN ---
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['login'])) {
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);

    if (empty($username) || empty($password)) {
        $error = "Por favor ingrese usuario y contraseña";
    } else {
        $conn = conectarBD();
        $sql = "SELECT id, username, password FROM login_user WHERE username = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows == 1) {
            $user = $result->fetch_assoc();

            if ($password === $user['password']) {
                // Generar sesion_id único de 64 bits
                $sesion_id_unico = bin2hex(random_bytes(8)); // 8 bytes = 64 bits

                // Variables de sesión
                $_SESSION['sesion_id'] = $sesion_id_unico;
                $_SESSION['user_id']   = $user['id'];
                $_SESSION['username']  = $user['username'];
                $_SESSION['loggedin']  = true;

                // Guardar en log_sistema
                $sql_log = "INSERT INTO log_sistema (sesion_id, usuario, fecha_inicio) VALUES (?, ?, NOW())";
                $stmt_log = $conn->prepare($sql_log);
                $stmt_log->bind_param("ss", $sesion_id_unico, $user['username']);
                $stmt_log->execute();
                $stmt_log->close();

                header("Location: conexionBD_leer_registrar_eliminar_editar_css_sesion.php");
                exit;
            } else {
                $error = "Contraseña incorrecta";
            }
        } else {
            $error = "Usuario no encontrado";
        }
        $stmt->close();
        $conn->close();
    }
}

// --- LOGOUT ---
if (isset($_GET['logout'])) {
    $conn = conectarBD();

    if (isset($_SESSION['sesion_id'])) {
        $sql_update = "UPDATE log_sistema 
                       SET fecha_cierre = NOW() 
                       WHERE sesion_id = ? AND fecha_cierre IS NULL";
        $stmt = $conn->prepare($sql_update);
        $stmt->bind_param("s", $_SESSION['sesion_id']);
        $stmt->execute();
        $stmt->close();
    }

    $conn->close();

    session_unset();
    session_destroy();
    header("Location: login.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Inicio de Sesión</title>
    <link rel="stylesheet" href="estilo_login.css">
</head>
<body>
    <h2>Iniciar Sesión</h2>

    <?php if (isset($error)): ?>
        <div style="color:red;"><?php echo $error; ?></div>
    <?php endif; ?>

    <form action="login.php" method="post">
        <label for="username">Usuario:</label>
        <input type="text" id="username" name="username" required>

        <label for="password">Contraseña:</label>
        <input type="password" id="password" name="password" required>

        <input type="submit" name="login" value="Iniciar Sesión">
    </form>
</body>
</html>
