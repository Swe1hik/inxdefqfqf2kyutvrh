<?php
session_start();

header('Content-Type: application/json');
header('Cache-Control: no-cache, must-revalidate');
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
// ini_set('error_log', '/path/to/your/php-error.log'); это добавлять если тебе нужно логирование!!!

$usersFile = __DIR__ . '/users.json';
$forumDataFile = __DIR__ . '/forum_data.json';


if ((!file_exists($usersFile) && !is_writable(__DIR__)) || (file_exists($usersFile) && !is_writable($usersFile))) {
    error_log("PHP ERROR: Cannot write to users file/directory: " . $usersFile);
    sendResponse(false, null, "Server configuration error (code: U1). Please contact admin.", 500);
}
if ((!file_exists($forumDataFile) && !is_writable(__DIR__)) || (file_exists($forumDataFile) && !is_writable($forumDataFile))) {
    error_log("PHP ERROR: Cannot write to forum data file/directory: " . $forumDataFile);
    sendResponse(false, null, "Server configuration error (code: F1). Please contact admin.", 500);
}


$initialForumData = [
    "discussions" => [],
    "crack-free" => [],
    "configs" => [],
    "reviews" => [],
    "suite-news" => []
];

function sendResponse($success, $data = null, $message = null, $statusCode = 200) {
    http_response_code($statusCode);
    $response = ['success' => (bool)$success];
    if ($data !== null) {
        $response['data'] = $data;
    }
    if ($message !== null) {
        $response['message'] = $message;
    }
    echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit();
}

function loadJsonData($jsonFile, $defaultData = []) {
    if (!file_exists($jsonFile)) {
        if (@file_put_contents($jsonFile, json_encode($defaultData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)) === false) {
            error_log("Error creating file: " . $jsonFile . " - Check permissions.");
            sendResponse(false, null, "Server configuration error (cannot create data file).", 500);
        }
        @chmod($jsonFile, 0664);
        return $defaultData;
    }

    $data = @file_get_contents($jsonFile);
     if ($data === false) {
        error_log("Error reading file: " . $jsonFile . " - Check permissions.");
        sendResponse(false, null, "Server configuration error (cannot read data file).", 500);
    }

    if (trim($data) === '') {
        return $defaultData;
    }

    $decoded = json_decode($data, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("Error decoding JSON from " . $jsonFile . ": " . json_last_error_msg() . " - Content: " . substr($data, 0, 200));
        sendResponse(false, null, "Server data error (invalid format). Please check data file: " . basename($jsonFile), 500);
    }
    if (!is_array($decoded)) {
         error_log("Decoded JSON is not an array in " . $jsonFile);
         return $defaultData;
    }

    return $decoded ?: $defaultData;
}

function saveJsonData($data, $jsonFile) {
     if (!is_array($data)) {
        error_log("Attempted to save non-array data to JSON file: " . $jsonFile);
        return false;
     }
    $jsonData = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    if ($jsonData === false) {
        error_log("Error encoding JSON for " . $jsonFile . ": " . json_last_error_msg());
        return false;
    }
    if (@file_put_contents($jsonFile, $jsonData, LOCK_EX) === false) {
        error_log("Error writing to file: " . $jsonFile . " - Check permissions.");
        return false;
    }
    return true;
}

function sanitize($data) {
     return htmlspecialchars(trim($data ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function isLoggedIn() {
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
}

function getUsername() {
    return isset($_SESSION['username']) ? $_SESSION['username'] : null;
}

function getUserId() {
    return isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null;
}


$action = $_REQUEST['action'] ?? null;

$forumData = null;
$users = null;

function getNextUserId($users) {
    if (empty($users)) {
        return 0;
    }
    $maxId = 0;
    foreach ($users as $user) {
        if (isset($user['id']) && is_numeric($user['id'])) {
            $maxId = max($maxId, (int)$user['id']);
        }
    }
    return $maxId + 1;
}


try {

    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        switch ($action) {
            case 'check_auth':
                if (isLoggedIn()) {
                    $users = loadJsonData($usersFile, []);
                    $user = null;
                    foreach ($users as $u) {
                        if (isset($u['id']) && $u['id'] == getUserId()) {
                            $user = $u;
                            break;
                        }
                    }
                    if ($user) {
                         $userData = [
                             'userId' => $user['id'],
                             'username' => sanitize($user['username'] ?? 'N/A'),
                             'email' => sanitize($user['email'] ?? ''),
                             'status' => sanitize($user['status'] ?? ''),
                             'joined' => isset($user['joined']) ? (int)$user['joined'] : 0
                         ];
                         sendResponse(true, $userData);
                     } else {
                          error_log("Auth check: Logged in user ID " . getUserId() . " not found in users file.");
                          session_unset();
                          session_destroy();
                          sendResponse(false, null, 'User data inconsistent. Please log in again.', 401);
                     }
                 } else {
                    sendResponse(true, null);
                }
                break;
            case 'get_categories':
                $forumData = loadJsonData($forumDataFile, $initialForumData);
                 $categories = [];
                 if (is_array($forumData)) {
                     foreach (array_keys($forumData) as $slug) {
                         $categories[$slug] = ucwords(str_replace('-', ' ', $slug));
                     }
                 } else {
                     error_log("Forum data is not an array in get_categories. File: " . $forumDataFile);
                 }
                sendResponse(true, $categories);
                break;

            case 'get_posts':
                $categorySlug = sanitize($_GET['category'] ?? '');
                if (empty($categorySlug)) {
                    sendResponse(false, null, 'Category not specified.', 400);
                }
                $forumData = loadJsonData($forumDataFile, $initialForumData);
                if (isset($forumData[$categorySlug]) && is_array($forumData[$categorySlug])) {
                    $posts = $forumData[$categorySlug];
                    usort($posts, function($a, $b) {
                        return ($b['timestamp'] ?? 0) <=> ($a['timestamp'] ?? 0);
                    });
                    $sanitizedPosts = [];
                    foreach ($posts as &$post) {
                        $sanitizedPost = [
                             'id' => sanitize($post['id'] ?? uniqid('err_')),
                             'title' => sanitize($post['title'] ?? 'Untitled'),
                             'username' => sanitize($post['username'] ?? 'Unknown'),
                             'user_id' => sanitize($post['user_id'] ?? null),
                             'timestamp' => isset($post['timestamp']) ? (int)$post['timestamp'] : 0
                         ];
                         $sanitizedPosts[] = $sanitizedPost;
                    }
                    sendResponse(true, $sanitizedPosts);
                } else {
                     if (!isset($forumData[$categorySlug])) {
                         error_log("Category slug not found in forum " . $categorySlug);
                     } elseif (!is_array($forumData[$categorySlug])) {
                         error_log("Forum data for category slug '" . $categorySlug . "' is not an array.");
                     }
                    sendResponse(true, []);
                }
                break;

            case 'get_post':
                $categorySlug = sanitize($_GET['category'] ?? '');
                $postId = sanitize($_GET['id'] ?? '');
                 if (empty($categorySlug) || empty($postId)) {
                     sendResponse(false, null, 'Category or Post ID missing.', 400);
                 }
                $forumData = loadJsonData($forumDataFile, $initialForumData);
                $foundPost = null;
                if (isset($forumData[$categorySlug]) && is_array($forumData[$categorySlug])) {
                    foreach ($forumData[$categorySlug] as $post) {
                         if (is_array($post) && isset($post['id']) && $post['id'] === $postId) {
                            $foundPost = [
                                 'id' => sanitize($post['id']),
                                 'title' => sanitize($post['title'] ?? 'Untitled'),
                                 'username' => sanitize($post['username'] ?? 'Unknown'),
                                 'user_id' => sanitize($post['user_id'] ?? null),
                                 'content' => sanitize($post['content'] ?? ''),
                                 'timestamp' => isset($post['timestamp']) ? (int)$post['timestamp'] : 0
                            ];
                            break;
                        }
                    }
                } else {
                     error_log("Category slug not found or not array in get_post: " . $categorySlug);
                }

                if ($foundPost) {
                    sendResponse(true, $foundPost);
                } else {
                    sendResponse(false, null, 'Post not found.', 404);
                }
                break;

            default:
                 if ($action !== null) {
                    sendResponse(false, null, 'Invalid GET action specified.', 400);
                 }
                 break;
        }
    }

    elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
        switch ($action) {
            case 'login':
                $username = trim($_POST['username'] ?? '');
                $password = $_POST['password'] ?? '';
                if (empty($username) || empty($password)) {
                    sendResponse(false, null, 'Username and password required.', 400);
                }
                $users = loadJsonData($usersFile, []);
                $loggedInUser = null;
                if (is_array($users)) {
                    foreach ($users as $user) {
                        if (is_array($user) && isset($user['username']) && isset($user['password'])) {
                            if ($user['username'] === $username) {
                                if (password_verify($password, $user['password'])) {
                                    $loggedInUser = $user;
                                    break;
                                }
                            }
                        } else {
                             error_log("Invalid user record found during login: " . print_r($user, true));
                        }
                    }
                } else {
                     error_log("Users data file is corrupted or not an array.");
                     sendResponse(false, null, "Server error during login (U2).", 500);
                }

                if ($loggedInUser) {
                     session_regenerate_id(true);
                    $_SESSION['user_id'] = $loggedInUser['id'];
                    $_SESSION['username'] = $loggedInUser['username'];
                    sendResponse(true, ['userId' => $loggedInUser['id'], 'username' => $loggedInUser['username']], 'Login successful!');
                } else {
                    sendResponse(false, null, 'Invalid username or password.', 401);
                }
                break;

            case 'register':
                $new_username = trim($_POST['new_username'] ?? '');
                $new_email = filter_var(trim($_POST['new_email'] ?? ''), FILTER_SANITIZE_EMAIL);
                $new_password = $_POST['new_password'] ?? '';

                if (empty($new_username) || !preg_match('/^[a-zA-Z0-9_]{3,20}$/', $new_username)) {
                     sendResponse(false, null, 'Username must be 3-20 alphanumeric characters or underscores.', 400);
                }
                if (empty($new_email) || !filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
                     sendResponse(false, null, 'Please provide a valid email address.', 400);
                }
                if (strlen($new_password) < 6) {
                     sendResponse(false, null, 'Password must be at least 6 characters long.', 400);
                }

                $users = loadJsonData($usersFile, []);
                $exists = false;
                 if (is_array($users)) {
                    foreach ($users as $user) {
                         if (is_array($user) && (isset($user['username']) && $user['username'] === $new_username || isset($user['email']) && $user['email'] === $new_email)) {
                            $exists = true;
                            break;
                        }
                    }
                 } else {
                      error_log("Users data file is corrupted or not an array during registration check.");
                      sendResponse(false, null, "Server error during registration (U3).", 500);
                 }

                if ($exists) {
                    sendResponse(false, null, 'Username or email already exists.', 409);
                }

                $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
                 if ($hashed_password === false) {
                     error_log("Password hashing failed for registration.");
                     sendResponse(false, null, 'Server error during registration (P1).', 500);
                 }

                $newUserId = getNextUserId($users);

                $newUser = [
                    'id' => $newUserId,
                    'username' => $new_username,
                    'email' => $new_email,
                    'password' => $hashed_password,
                     'status' => 'Standard',
                     'joined' => time()
                ];
                $users[] = $newUser;

                if (saveJsonData($users, $usersFile)) {
                    sendResponse(true, null, 'Registration successful! Please log in.');
                } else {
                    sendResponse(false, null, 'Error saving registration data.', 500);
                }
                break;

            case 'create_post':
                if (!isLoggedIn()) {
                    sendResponse(false, null, 'Authentication required.', 401);
                }
                $categorySlug = sanitize($_POST['category'] ?? '');
                $title = sanitize($_POST['post_title'] ?? '');
                $content = sanitize($_POST['post_content'] ?? '');
                $userId = getUserId();
                $username = getUsername();

                if (empty($categorySlug) || empty($title) || empty($content)) {
                     sendResponse(false, null, 'Category, title, and content are required.', 400);
                 }

                 $forumData = loadJsonData($forumDataFile, $initialForumData);
                if (!isset($forumData[$categorySlug]) || !is_array($forumData[$categorySlug])) {
                     sendResponse(false, null, 'Invalid category specified.', 400);
                 }

                $newPost = [
                    'id' => uniqid('post_'),
                    'title' => $title,
                    'content' => $content,
                    'user_id' => $userId,
                    'username' => $username,
                    'timestamp' => time()
                ];
                array_unshift($forumData[$categorySlug], $newPost);

                if (saveJsonData($forumData, $forumDataFile)) {
                    $newPost['title'] = sanitize($newPost['title']);
                    $newPost['username'] = sanitize($newPost['username']);
                    $newPost['content'] = sanitize($newPost['content']);
                    sendResponse(true, $newPost, 'Post created successfully!');
                } else {
                    sendResponse(false, null, 'Error saving post.', 500);
                }
                break;

             case 'delete_post':
                if (!isLoggedIn()) {
                    sendResponse(false, null, 'Authentication required.', 401);
                }
                $categorySlug = sanitize($_POST['category'] ?? '');
                $postId = sanitize($_POST['id'] ?? '');
                 if (empty($categorySlug) || empty($postId)) {
                     sendResponse(false, null, 'Category or Post ID missing.', 400);
                 }
                $userId = getUserId();
                $forumData = loadJsonData($forumDataFile, $initialForumData);
                $postIndex = -1;
                $foundPost = null;

                 if (!isset($forumData[$categorySlug]) || !is_array($forumData[$categorySlug])) {
                     sendResponse(false, null, 'Category not found.', 404);
                 }

                foreach ($forumData[$categorySlug] as $index => $post) {
                     if (is_array($post) && isset($post['id']) && $post['id'] === $postId) {
                        $postIndex = $index;
                        $foundPost = $post;
                        break;
                    }
                }

                if ($postIndex === -1) {
                    sendResponse(false, null, 'Post not found.', 404);
                }

                if (!isset($foundPost['user_id']) || $foundPost['user_id'] != $userId) {
                    sendResponse(false, null, 'You are not authorized to delete this post.', 403);
                }

                array_splice($forumData[$categorySlug], $postIndex, 1);

                if (saveJsonData($forumData, $forumDataFile)) {
                    sendResponse(true, null, 'Post deleted successfully!');
                } else {
                    sendResponse(false, null, 'Error saving changes after deletion.', 500);
                }
                break;

             case 'logout':
                 session_unset();
                 session_destroy();
                 if (ini_get("session.use_cookies")) {
                     $params = session_get_cookie_params();
                     setcookie(session_name(), '', time() - 42000,
                         $params["path"], $params["domain"],
                         $params["secure"], $params["httponly"]
                     );
                 }
                 sendResponse(true, null, 'Logged out successfully.');
                 break;

            default:
                sendResponse(false, null, 'Invalid POST action specified.', 400);
        }
    }

    elseif ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
         http_response_code(204);
         exit();
    }
     else {
        sendResponse(false, null, 'Method not allowed.', 405);
    }

} catch (Throwable $e) {
    error_log("PHP UNCAUGHT ERROR: " . $e->getMessage() . " in " . $e->getFile() . " on line " . $e->getLine());
    sendResponse(false, null, 'An unexpected server error occurred.', 500);
}
?>
