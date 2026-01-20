<?php
// Vulnerable PHP Script - SQL Injection Example
// WARNING: This code is intentionally vulnerable for educational purposes only

$host = "localhost";
$user = "root";
$password = "";
$database = "webapp_db";

// Connect to database (simulated - commented out for safety)
// $conn = new mysqli($host, $user, $password, $database);

// VULNERABLE CODE - Direct user input in SQL query
if (isset($_GET['user_id'])) {
    $user_id = $_GET['user_id'];  // User input directly from URL
    
    // DANGEROUS: Unsanitized query construction
    $query = "SELECT * FROM users WHERE id = '" . $user_id . "'";
    
    // This query is vulnerable to SQL Injection
    // Example attack: ?user_id=1' OR '1'='1
    // Would execute: SELECT * FROM users WHERE id = '1' OR '1'='1'
    // This bypasses authentication and returns all users
    
    // echo "Executing: " . $query;
    // $result = $conn->query($query);
}

// Another vulnerable example with search functionality
if (isset($_GET['search'])) {
    $search_term = $_GET['search'];  // Unsanitized user input
    
    // VULNERABLE: Direct concatenation in SQL query
    $search_query = "SELECT title, content FROM articles WHERE title LIKE '%" . $search_term . "%'";
    
    // Example attack: ?search=test' UNION SELECT username, password FROM admin_users WHERE '1'='1
    // This could extract sensitive admin credentials
    
    // $search_result = $conn->query($search_query);
}

// Vulnerable login form
if ($_POST['login']) {
    $username = $_POST['username'];  // No sanitization
    $password = $_POST['password'];  // No sanitization
    
    // CRITICAL VULNERABILITY: Authentication bypass possible
    $login_query = "SELECT * FROM users WHERE username = '" . $username . "' AND password = '" . $password . "'";
    
    // Attacker can bypass: username = admin' --
    // This would execute: SELECT * FROM users WHERE username = 'admin' -- ' AND password = '...'
    // The -- comments out the password check
}

// CORRECT WAY (Prepared Statements):
/*
$prepared_query = "SELECT * FROM users WHERE id = ?";
$stmt = $conn->prepare($prepared_query);
$stmt->bind_param("s", $_GET['user_id']);
$stmt->execute();
$result = $stmt->get_result();
*/

?>
<html>
<head>
    <title>Vulnerable Web Application</title>
</head>
<body>
    <h1>User Search</h1>
    <form method="GET">
        <input type="text" name="user_id" placeholder="Enter User ID">
        <button type="submit">Search</button>
    </form>
    
    <h1>Search Articles</h1>
    <form method="GET">
        <input type="text" name="search" placeholder="Search articles...">
        <button type="submit">Search</button>
    </form>
</body>
</html>
