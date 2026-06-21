const express = require('express')
const bcrypt = require('bcrypt')
const session = require('express-session')
const crypto = require('crypto')
const pool = require('./db')
const app = express()
app.set('view engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(session({
    secret: 'task4-secret',
    resave: false,
    saveUninitialized: false
}))
function getSelectedIds(request) {
    if (!request.body.ids) {
        return []
    }
    return Array.isArray(request.body.ids)
        ? request.body.ids
        : [request.body.ids]
}
async function updateUsersStatus(ids, status) {
    if (ids.length === 0) {
        return
    }
    await pool.query(
        'UPDATE users SET status = $1 WHERE id = ANY($2)',
        [status, ids]
    )
}
async function requireActiveUser(request, response, next) {
    if (!request.session.userId) {
        response.redirect('/login')
        return
    }
    const result = await pool.query(
        'SELECT id, status FROM users WHERE id = $1',
        [request.session.userId]
    )
    if (result.rows.length === 0 || result.rows[0].status === 'blocked') {
        request.session.destroy(function () {
            response.redirect('/login')
        })
        return
    }
    next()
}
app.get('/', function (request, response) {
    response.redirect('/register')
})
app.get('/register', function (request, response) {
    response.render('register')
})
app.post('/register', async function (request, response) {
    const name = request.body.name.trim()
    const email = request.body.email.trim().toLowerCase()
    const password = request.body.password
    const passwordHash = await bcrypt.hash(password, 10)
    const verificationToken = crypto.randomUUID()
    try {
        await pool.query(
            'INSERT INTO users(name, email, password_hash, status, verification_token) VALUES($1, $2, $3, $4, $5)',
            [name, email, passwordHash, 'unverified', verificationToken]
        )
        response.send(
            'Registration successful. <a href="/verify/' +
            verificationToken +
            '">Click This Button</a>'
        )
    } catch (error) {
        if (error.code === '23505') {
            response.send('Email already exists')
            return
        }
        response.send('Registration failed')
    }
})
app.get('/verify/:token', async function (request, response) {
    await pool.query(
        "UPDATE users SET status = 'active' WHERE verification_token = $1 AND status <> 'blocked'",
        [request.params.token]
    )
    response.send('Email verified. <a href="/login">Login</a>')
})
app.get('/login', function (request, response) {
    response.render('login')
})
app.post('/login', async function (request, response) {
    const email = request.body.email.trim().toLowerCase()
    const password = request.body.password
    const result = await pool.query(
        'SELECT * FROM users WHERE email = $1',
        [email]
    )
    if (result.rows.length === 0) {
        response.send('Wrong email or password')
        return
    }
    const user = result.rows[0]
    if (user.status === 'blocked') {
        response.send('User is blocked')
        return
    }
    const passwordIsCorrect = await bcrypt.compare(password, user.password_hash)
    if (!passwordIsCorrect) {
        response.send('Wrong email or password')
        return
    }
    await pool.query(
        'UPDATE users SET last_login_at = NOW() WHERE id = $1',
        [user.id]
    )
    request.session.userId = user.id
    response.redirect('/users')
})
app.get('/users', requireActiveUser, async function (request, response) {
    const result = await pool.query(
        'SELECT id, name, email, last_login_at, status FROM users ORDER BY last_login_at DESC NULLS LAST'
    )
    response.render('users', {
        users: result.rows
    })
})
app.post('/users/block', requireActiveUser, async function (request, response) {
    await updateUsersStatus(getSelectedIds(request), 'blocked')
    response.redirect('/users')
})
app.post('/users/unblock', requireActiveUser, async function (request, response) {
    await updateUsersStatus(getSelectedIds(request), 'unverified')
    response.redirect('/users')
})
app.post('/users/delete', requireActiveUser, async function (request, response) {
    const ids = getSelectedIds(request)
    if (ids.length > 0) {
        await pool.query(
            'DELETE FROM users WHERE id = ANY($1)',
            [ids]
        )
    }
    response.redirect('/users')
})
app.post('/users/delete-unverified', requireActiveUser, async function (request, response) {
    await pool.query(
        "DELETE FROM users WHERE status = 'unverified'"
    )
    response.redirect('/users')
})
app.get('/logout', function (request, response) {
    request.session.destroy(function () {
        response.redirect('/login')
    })
})
app.listen(3000, function () {
    console.log('Server started')
})