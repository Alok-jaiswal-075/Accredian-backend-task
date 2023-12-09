const express = require('express')
const mysql = require('mysql')
const cors = require('cors')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser')

const app = express();
app.use(cookieParser());

const corsOptions = {
    origin: 'http://localhost:3000', // Replace with your frontend URL
    credentials: true, // Enable credentials
  };
  
app.use(cors(corsOptions));

app.use(express.json())

const JWT_SECRET = "this is a #$#@# very tough secret @&%^#&&**"


const db = mysql.createConnection({
    host : "localhost",
    user : "root",
    password : "",
    database : "user"
})


app.get('/home', async (req, res) => {
    try {
        const token = req.cookies.token;
        if (!token) {
            return res.status(400).json("User not logged in");
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const sql = "SELECT * FROM users WHERE `username` = ? OR `email` = ?";
        const values = [decoded.username, decoded.username];

        db.query(sql, values, (err, data) => {
            if (err) {
                console.error("Database error:", err); // Log the database error
                return res.status(500).json("Database error");
            }

            if (data.length > 0) {
                return res.status(200).json(data[0].username);
            } else {
                return res.status(404).json("User not found");
            }
        });
    } catch (error) {
        console.error("Error:", error); // Log any other errors
        return res.status(400).json("Invalid token or authentication failed");
    }
});

app.get('/logout', async (req, res) => {
    res.clearCookie('token').json({'msg':'Logged out successfully'})
});



app.post('/signup', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json("Please provide username, email, and password");
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const sql = "INSERT INTO users (`username`, `email`, `password`) VALUES (?, ?, ?)";
        const values = [username, email, hashedPassword];

        db.query(sql, values, (err, data) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json("Username or email already exists");
                }
                return res.status(400).json("Error adding user");
            }
            return res.status(200).json(data);
        });
    } catch (error) {
        return res.status(400).json("Error hashing password");
    }
});


app.post('/login', async (req, res) => {
    try {
        const sql = "SELECT * FROM users WHERE `username` = ? OR `email` = ?";
        const values = [req.body.username_email, req.body.username_email]; // Changed to one parameter for username or email

        //console.log(req.body);
        
        db.query(sql, values, async (err, data) => {
            if (err) {
                return res.json("Error logging user in");
            }
            if (data.length > 0) {
                const hashedPasswordFromDB = data[0].password;  
                const inputPassword = req.body.password;
                //console.log(hashedPasswordFromDB);
                //console.log(inputPassword);

                try {
                    const result = await bcrypt.compare(inputPassword, hashedPasswordFromDB);
                    if (result) {
                        const token = jwt.sign({ "username": req.body.username_email}, JWT_SECRET);
                        res.cookie('token', token,{
                            expires:new Date(Date.now() + 25892000000),
                            secure: true, 
                            httpOnly: true
                        });
                        res.status(200).json({ msg: 'User signed in successfully'})
                    } else {
                        return res.status(400).json("Incorrect Credentials");
                    }
                } catch (error) {
                    return res.status(400).json("Incorrect Credentials");
                }
            } else {
                return res.status(400).json("User not found");
            }
        });
    } catch (error) {
        return res.status(400).json("Error logging in");
    }
});




app.listen(8081,()=>{
    console.log("listening")
})