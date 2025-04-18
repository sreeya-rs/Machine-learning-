<?php
// Start session to store user login status
session_start();

// Database connection settings
$host = "localhost";
$dbUsername = "root"; // Change to your database username
$dbPassword = 12345678; // Change to your database password
$dbName = "safari"; // Change to your database name

// Initialize variables
$error = false;
$errorMessage = "";

// Process the form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Get form data
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    $remember = isset($_POST['remember']) ? true : false;
    
    // Validate inputs
    if (empty($email)) {
        $error = true;
        $errorMessage = "Email is required";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = true;
        $errorMessage = "Please enter a valid email address";
    } elseif (empty($password)) {
        $error = true;
        $errorMessage = "Password is required";
    } else {
        // Create database connection
        $conn = new mysqli($host, $dbUsername, $dbPassword, $dbName);
        
        // Check connection
        if ($conn->connect_error) {
            $error = true;
            $errorMessage = "Connection failed: " . $conn->connect_error;
        } else {
            // Prepare SQL statement to prevent SQL injection
            $sql = "SELECT * FROM users WHERE email = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows > 0) {
                // User found, verify password
                $user = $result->fetch_assoc();
                
                if (password_verify($password, $user['password'])) {
                    // Password is correct
                    
                    // Set session variables
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['user_name'] = $user['fullName'];
                    $_SESSION['user_email'] = $user['email'];
                    $_SESSION['logged_in'] = true;
                    
                    // Set remember me cookie if selected (30 days expiration)
                    if ($remember) {
                        $token = bin2hex(random_bytes(32)); // Generate random token
                        
                        // Store token in database (you might want to create a tokens table for this)
                        // For now, we'll just set the cookie
                        setcookie('safari_remember', $token, time() + (86400 * 30), "/"); // 30 days
                    }
                    
                    // Redirect to home page
                    header("Location: home1.html");
                    exit();
                } else {
                    // Password is incorrect
                    $error = true;
                    $errorMessage = "Invalid email or password";
                    echo"". $errorMessage ."";
                }
            } else {
                // User not found
                $error = true;
                $errorMessage = "Invalid email or password";
                echo "". $errorMessage ."";
            }
            
            $stmt->close();
            $conn->close();
        }
    }
}
?>