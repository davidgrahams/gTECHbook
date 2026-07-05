require('dotenv').config();
const jwt = require('jsonwebtoken');
const marked = require('marked');
const sanitiseHtml = require('sanitize-html');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const express = require('express');
const db = require('better-sqlite3')('ourApp.db');
db.pragma('journal_mode = WAL');

//database setup here
const createTables = db.transaction(() => {
db.prepare(
    `
    CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username STRING NOT NULL UNIQUE,
    password STRING NOT NULL
    )
    `
).run()

db.prepare(
    `
    CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdDate TEXT,
    title STRING NOT NULL,
    body TEXT NOT NULL,
    authorid INTEGER,
    FOREIGN KEY (authorid) REFERENCES users(id)
    )
    `
).run()
});

createTables()

//database setup ends here

const app = express();

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));
app.use(cookieParser())

app.use(function(req, res, next) {
//make markdown function available
res.locals.filterUserHTML = function(content) {
    return sanitiseHtml(marked.parse(content), {
        allowedTags: ['p', 'br', 'ul', 'ol', 'li', 'strong', 'bold', 'i', 'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'],
        allowedAttributes: {}
    })
}

res.locals.errors = []

//try to decode the cookie
try {
    const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET)
    req.user = decoded
} catch (err) {
    req.user = false
}

res.locals.user = req.user
console.log(req.user)

next()
})

    app.get('/', (req, res) => {
        if (req.user) {
            const statement = db.prepare('SELECT * FROM posts WHERE authorid=? ORDER BY createdDate DESC')
            const posts = statement.all(req.user.userid)
            return res.render('dashboard', { posts })
        }

  res.render('homepage');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/logout', (req, res) => {
  res.clearCookie('ourSimpleApp');
  res.redirect('/');
});

app.post('/login', (req, res) => {
  let errors = []

    if (typeof req.body.username !== 'string') req.body.username = ''
    if (typeof req.body.password !== 'string') req.body.password  = ''

    if (req.body.username.trim() =='') errors = ['invalid username/password'];
      if (req.body.password == '') errors = ['invalid username/password'];

      if (errors.length) {
        return res.render("login", {errors});
        };

        const userInQuestionStatement = db.prepare('SELECT * FROM users WHERE username = ?');
        const userInQuestion = userInQuestionStatement.get(req.body.username);

if (!userInQuestion) {
     errors = ['invalid username/password'];
     return res.render("login", {errors});
}

const matchOrNot = bcrypt.compareSync(req.body.password, userInQuestion.password);
if (!matchOrNot) {
    errors = ['invalid username/password'];
    return res.render("login", {errors});
}

    const ourTokenValue = jwt.sign(
{exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24), skycolor: 'blue', userid: userInQuestion.id, username: userInQuestion.username},
process.env.JWTSECRET
)

res.cookie('ourSimpleApp', ourTokenValue, {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60 * 24
    })

res.redirect('/')
})

function mustBeLoggedIn(req, res, next) {
    if (req.user) {
       return next()
    }
    res.redirect('/')
    next()
}

app.get('/create-post', mustBeLoggedIn, (req, res) => {
    res.render('create-post');
});

function sharedPostValidation(req) {
    const errors = []

    if (typeof req.body.title !== 'string') req.body.title = ''
    if (typeof req.body.body !== 'string') req.body.body  = ''

    //TRIM SANITISE OR STRIP OUT HTML
    req.body.title = sanitiseHtml(req.body.title.trim(), {allowedTags: [], allowedAttributes: {}})
    req.body.body = sanitiseHtml(req.body.body.trim(), {allowedTags: [], allowedAttributes: {}})

if (!req.body.title) errors.push('you must provide title');
if (!req.body.body) errors.push('you must provide content');

    return errors
}

app.get('/edit-post/:id', mustBeLoggedIn, (req, res) => {
    //try to look up the post in question
    const statement = db.prepare('SELECT * FROM posts WHERE id = ?')
    const post = statement.get(req.params.id)

    if (!post) {
        return res.redirect('/')
    }

    //if you are not the author redirect to homepage
    if (post.authorid !== req.user.userid) {
        return res.redirect('/')
    }

    //otherwise render the edit-post template 
    res.render('edit-post', {post})
})

app.post('/edit-post/:id', mustBeLoggedIn, (req, res) => {
  //try to look up the post in question
    const statement = db.prepare('SELECT * FROM posts WHERE id = ?')
    const post = statement.get(req.params.id)

    if (!post) {
        return res.redirect('/')
    }

    //if you are not the author redirect to homepage
    if (post.authorid !== req.user.userid) {
        return res.redirect('/')
    }

    const errors = sharedPostValidation(req)

if (errors.length) {
    return res.render("edit-post", {errors, })
  }

  const updateStatement = db.prepare('UPDATE posts SET title = ?, body = ? WHERE id = ?')
  updateStatement.run(req.body.title, req.body.body, req.params.id)

res.redirect(`/post/${req.params.id}`)
})

app.post('/delete-post/:id',mustBeLoggedIn, (req, res) => {
 //try to look up the post in question
    const statement = db.prepare('SELECT * FROM posts WHERE id = ?')
    const post = statement.get(req.params.id)

    if (!post) {
        return res.redirect('/')
    }

    //if you are not the author redirect to homepage
    if (post.authorid !== req.user.userid) {
        return res.redirect('/')
    }

    const deleteStatement = db.prepare('DELETE FROM posts WHERE id = ?')
    deleteStatement.run(req.params.id)

    res.redirect('/')
})

app.get('/post/:id', (req, res) => {
    const statement = db.prepare('SELECT posts.*, users.username FROM  posts INNER JOIN users ON posts.authorid = users.id WHERE posts.id = ?')
    const post = statement.get(req.params.id)

    if (!post) {
        return res.redirect('/')
    }

 const isAuthor = post.authorid === req.user.userid

    res.render('single-post', {post, isAuthor})
})
app.post('/create-post', mustBeLoggedIn, (req, res) => {
   const errors = sharedPostValidation(req)

if (errors.length) {
    return res.render("create-post", {errors});
}

//save the post into database
const ourstatement = db.prepare('INSERT INTO posts (title, body, createdDate, authorid) VALUES (?, ?, ?, ?)')
const result = ourstatement.run(req.body.title, req.body.body, new Date().toISOString(), req.user.userid)

const getPostStatement = db.prepare('SELECT * FROM posts WHERE ROWid = ?')
const realPost = getPostStatement.get(result.lastInsertRowid)

res.redirect(`/post/${realPost.id}`)
});

app.post('/register', (req, res) => {
  const errors = []

if (typeof req.body.username !== 'string') req.body.username =''
if (typeof req.body.password !== 'string') req.body.password  = ''
 
req.body.username = req.body.username.trim()
 
if (!req.body.username) errors.push('you must provide username');
if (req.body.username && req.body.username.length < 3) errors.push('username must be at least 3 characters');
if (req.body.username && req.body.username.length > 10) errors.push('username must be at least 10 characters');
if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push('username must contain leters and numbers');

//check if user name exist already
const UsernameStatement = db.prepare('SELECT * FROM users WHERE username = ?')
const UsernameCheck = UsernameStatement.get(req.body.username)

if (UsernameCheck) errors.push('that username is already exists')

if (!req.body.password) errors.push('you must provide password');
if (req.body.password && req.body.password.length < 12) errors.push('Password must be at least 12 characters');
if (req.body.password && req.body.password.length > 70) errors.push('Password must be at most 70 characters');

if (errors.length) {
    return res.render("homepage", {errors});
}

//save the user into database
const salt = bcrypt.genSaltSync(10)
const password = bcrypt.hashSync(req.body.password, salt)

const ourStatement = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)')
const result = ourStatement.run(req.body.username, password)

const lookupStatement = db.prepare('SELECT * FROM users WHERE ROWid = ?')
const ourUser = lookupStatement.get(result.lastInsertRowid)

//log the user by giving them a cookie
const ourTokenValue = jwt.sign(
{exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24), skycolor: 'blue', userid: ourUser.id, username: ourUser.username},
process.env.JWTSECRET
)

res.cookie('ourSimpleApp', ourTokenValue, {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60 * 24 * 7
    })

res.redirect('/')
})

app.listen(3000)
