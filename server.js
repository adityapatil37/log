const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'sealtod'; 


const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'mydatabase'
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to the database');
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


app.post('/signup', 

    [body('username').notEmpty(), body('password').notEmpty(), body('role').isIn(['Admin', 'Manager', 'Employee'])],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        
        const { username, password, role } = req.body;
        
        try {

            const hashedPassword = await bcrypt.hash(password, 10);
            

            const query = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
            db.query(query, [username, hashedPassword, role], (err, result) => {
                if (err) {
                    console.error(err);
                    return res.status(500).send('Error signing up');
                }
                res.status(200).send('User signed up successfully');
            });
        } catch (error) {
            console.error(error);
            res.status(500).send('Error processing sign up');
        }
    }
);


app.post('/login',

    [body('username').notEmpty(), body('password').notEmpty()],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, password } = req.body;
        
        try {

            const query = 'SELECT * FROM users WHERE username = ?';
            db.query(query, [username], async (err, results) => {
                if (err) {
                    console.error(err);
                    return res.status(500).send('Error logging in');
                }
                
                if (results.length === 0) {
                    return res.status(401).send('Invalid credentials');
                }
                
                const user = results[0];
                

                const isMatch = await bcrypt.compare(password, user.password);
                
                if (isMatch) {

                    const token = jwt.sign(
                        { userId: user.id, role: user.role },
                        SECRET_KEY,
                        { expiresIn: '1h' }
                    );
                    
                    res.status(200).json({
                        message: 'Login successful',
                        token,
                        role: user.role
                    });
                } else {
                    res.status(401).send('Invalid credentials');
                }
            });
        } catch (error) {
            console.error(error);
            res.status(500).send('Error processing login');
        }
    }
);

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        
        req.user = user;
        next();
    });
}

// Route for Admin
app.get('/admin', authenticateToken, (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).send('Access denied');
    }
    res.send('Admin page');
});

// Route for Manager
app.get('/manager', authenticateToken, (req, res) => {
    if (req.user.role !== 'Manager') {
        return res.status(403).send('Access denied');
    }
    res.send('Manager page');
});

// Route for Employee
app.get('/employee', authenticateToken, (req, res) => {
    if (req.user.role !== 'Employee') {
        return res.status(403).send('Access denied');
    }
    res.send('Employee page');
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
