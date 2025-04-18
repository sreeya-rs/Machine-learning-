<?php
// Database connection settings
$host = "localhost";
$dbUsername = "root"; // Change to your database username
$dbPassword = 12345678; // Change to your database password
$dbName = "safari"; // Change to your database name

// Initialize variables
$success = false;
$error = false;
$errorMessages = [];

// Create database connection
$conn = new mysqli($host, $dbUsername, $dbPassword);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Check if database exists, if not create it
$checkDbQuery = "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '$dbName'";
$result = $conn->query($checkDbQuery);

if ($result->num_rows == 0) {
    // Create database
    $createDbQuery = "CREATE DATABASE $dbName";
    if ($conn->query($createDbQuery) === TRUE) {
        // Database created successfully
    } else {
        $error = true;
        $errorMessages['database'] = "Error creating database: " . $conn->error;
    }
}

// Connect to the created/existing database
$conn->select_db($dbName);

// Check if users table exists, if not create it
$checkTableQuery = "SHOW TABLES LIKE 'users'";
$result = $conn->query($checkTableQuery);

if ($result->num_rows == 0) {
    // Create users table
    $createTableQuery = "CREATE TABLE users (
        id INT(11) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        fullName VARCHAR(100) NOT NULL,
        email VARCHAR(100) NOT NULL UNIQUE,
        phone VARCHAR(20) NOT NULL,
        gender VARCHAR(10) NOT NULL,
        password VARCHAR(255) NOT NULL,
        country VARCHAR(50) NOT NULL,
        newsletter TINYINT(1) DEFAULT 0,
        terms TINYINT(1) DEFAULT 1,
        registrationDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )";
    
    if ($conn->query($createTableQuery) !== TRUE) {
        $error = true;
        $errorMessages['database'] = "Error creating table: " . $conn->error;
    }
}

// Process form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Get form data
    $fullName = $_POST['fullName'] ?? '';
    $email = $_POST['email'] ?? '';
    $phone = $_POST['phone'] ?? '';
    $gender = $_POST['gender'] ?? '';
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirmPassword'] ?? '';
    $country = $_POST['country'] ?? '';
    $newsletter = isset($_POST['newsletter']) ? 1 : 0;
    $terms = isset($_POST['terms']) ? 1 : 0;
    
    // Validate form data
    $valid = true;
    
    // Name validation
    if (!preg_match("/^[a-zA-Z\s]{3,50}$/", $fullName)) {
        $errorMessages['name'] = 'Name should contain only letters and spaces (3-50 characters)';
        $valid = false;
    }
    
    // Email validation
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errorMessages['email'] = 'Please enter a valid email address';
        $valid = false;
    }
    
    // Phone validation (exactly 10 digits)
    if (!preg_match("/^[0-9]{10}$/", $phone)) {
        $errorMessages['phone'] = 'Please enter a valid 10-digit phone number';
        $valid = false;
    }
    
    // Gender validation
    if (empty($gender) || !in_array($gender, ['Male', 'Female', 'Other'])) {
        $errorMessages['gender'] = 'Please select a valid gender';
        $valid = false;
    }
    
    // Password validation
    if (!preg_match("/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/", $password)) {
        $errorMessages['password'] = 'Password must contain at least 8 characters, including uppercase, lowercase, number, and special character';
        $valid = false;
    }
    
    // Confirm password validation
    if ($password !== $confirmPassword) {
        $errorMessages['confirm'] = 'Passwords do not match';
        $valid = false;
    }
    
    // Terms validation
    if (!$terms) {
        $errorMessages['terms'] = 'You must accept the terms and conditions';
        $valid = false;
    }
    
    // If all validations pass
    if ($valid) {
        // Check if email already exists
        $checkEmailQuery = "SELECT * FROM users WHERE email = ?";
        $stmt = $conn->prepare($checkEmailQuery);
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $error = true;
            $errorMessages['email'] = 'This email is already registered. Please use a different email.';
        } else {
            // Hash the password before storing
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
            
            // Prepare SQL statement to prevent SQL injection
            $insertQuery = "INSERT INTO users (fullName, email, phone, gender, password, country, newsletter, terms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
            $stmt = $conn->prepare($insertQuery);
            $stmt->bind_param("ssssssii", $fullName, $email, $phone, $gender, $hashedPassword, $country, $newsletter, $terms);
            
            // Execute query
            if ($stmt->execute()) {
                // Close the database connection before redirecting
                $stmt->close();
                $conn->close();
                
                // Set a success message in session if needed
                session_start();
                $_SESSION['registration_success'] = true;
                
                // Ensure there's no output before the redirect
                ob_clean();
                
                // Redirect to login page on successful registration
                echo "<script>window.location.href = 'login1.html';</script>";
                echo "<script>setTimeout(function() { window.location.href = 'login1.html'; }, 1000);</script>";
                header("Location: login1.html");
                exit();
            } else {
                $error = true;
                $errorMessages['database'] = "Registration failed: " . $stmt->error;
            }
        }
    } else {
        $error = true;
    }
}

$conn->close();

// If there were errors and no redirect happened, display them
if ($error) {
    // Output errors directly (for testing)
    foreach ($errorMessages as $key => $value) {
        echo "$key: $value <br>";
    }
    
    // You could also redirect back to the form with error parameters
    // header("Location: index1.html?error=true");
    exit();
}
?>