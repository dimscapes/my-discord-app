require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const path = require('path');
const fs = require('fs');
const app = express();
const PORT = 3000;
const scopes = ['identify'];
let users = {};
let availableRoles = ['Cape Team', 'Cape Head', 'Customer Support', 'Support Head', 'Moderation', 'Moderation Administration', 'Administration'];

const usersDataFile = path.join(__dirname, 'usersData.json');
let usersData;
try {
    usersData = JSON.parse(fs.readFileSync(usersDataFile, 'utf8'));
} catch (err) {
    console.error('Error loading users data:', err);
    usersData = {};
}

function saveUsersData() {
    fs.writeFileSync(usersDataFile, JSON.stringify(usersData, null, 2), 'utf8');
}

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json()); // For parsing application/json
app.use(express.urlencoded({ extended: true })); // For parsing application/x-www-form-urlencoded

// Configure session middleware
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: true,  // Change to true when using HTTPS
        maxAge: 1000 * 60 * 60 * 24 * 7  // 1 week
    }
}));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: process.env.DISCORD_CALLBACK_URL,
    scope: scopes
},
(accessToken, refreshToken, profile, done) => {
    if (!usersData[profile.id]) {
        return done(null, false, { message: 'You are not authorized to log in.' });
    }

    // Save user profile information
    users[profile.id] = {
        id: profile.id,
        username: profile.username,
        avatar: profile.avatar,
        discriminator: profile.discriminator
    };

    // Log the session here
    console.log("Session before done:", profile);
    return done(null, profile);
}));

// Serialize user into the session
passport.serializeUser((user, done) => {
    done(null, user.id); // Store only the user ID, not the entire object
});

passport.deserializeUser((id, done) => {
    console.log('Deserializing user with ID:', id); // Add this log
    const user = usersData[id]; // Or fetch the user from another source
    if (user) {
        console.log('User found in deserializeUser:', user); // Add this log
        done(null, user);
    } else {
        console.log('No user found for ID:', id); // Add this log
        done(null, false); // No user found, session might be invalid
    }
});

// LINKS
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/terms', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'terms.html'));
});
app.get('/privacy', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});
app.get('/discord', (req, res) => {
    res.redirect('https://discord.gg/9zk4umeHcD');
});
app.get('/staff', ensureAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'staff.html'));
});
app.get('/cape', ensureCapeTeam, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'cape.html'));
});
app.get('/mod', ensureModeration, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'mod.html'));
});
app.get('/admin', ensureAdministration, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error('Error logging out:', err);
        }
        res.redirect('/');
    });
});
app.get('/auth/discord', (req, res, next) => {
    if (req.isAuthenticated()) {
        return res.redirect('/staff');  // Redirect if already logged in
    }
    next();
}, passport.authenticate('discord'));
app.get('/auth/discord/callback',
    passport.authenticate('discord', { failureRedirect: '/' }),
    (req, res) => {
        console.log('User authenticated successfully:', req.user);
        console.log("Session after authentication:", req.session);
        res.redirect('/staff');
    }
);
app.get('/api/user', ensureAuthenticated, (req, res) => {
    const username = users[req.user.id]?.username || "User"; // Get the username from the users object
    res.json({ username }); // Send the username as a JSON response
});
// Route to get the current user's roles
app.get('/api/user/roles', ensureAuthenticated, (req, res) => {
    const userID = req.user.id;
    const roles = usersData[userID]?.roles || [];
    console.log("HEY RO ", roles);
    res.json({ roles });  // Send the user's roles as a JSON response
});
app.get('/api/admin/users', ensureAdministration, (req, res) => {
    res.json(usersData);  // Send all users and their roles
});

app.get('/api/admin/roles', ensureAdministration, (req, res) => {
    res.json(availableRoles);  // Send all available roles
});

// Route to add a new user (admin only)
app.post('/api/admin/users', ensureAdministration, (req, res) => {
    const { userId, roles, nickname } = req.body;
    if (userId && Array.isArray(roles) && nickname) {
        usersData[userId] = { roles, nickname };
        saveUsersData();  // Save updated users data to the file
        res.status(200).json({ message: 'User added/updated successfully' });
    } else {
        res.status(400).json({ message: 'Invalid input' });
    }
});

app.delete('/api/admin/users/:id', ensureAdministration, (req, res) => {
    const userId = req.params.id;
    if (usersData[userId]) {
        delete usersData[userId];
        saveUsersData();  // Save after deleting the user
        res.status(200).json({ message: 'User deleted successfully' });
    } else {
        res.status(404).json({ message: 'User not found' });
    }
});


// Route to add/remove roles from a user
app.post('/api/admin/users/:id/roles', ensureAdministration, (req, res) => {
    const userId = req.params.id;
    const { roles } = req.body;
    if (usersData[userId] && Array.isArray(roles)) {
        usersData[userId].roles = roles;  // Update user roles
        res.status(200).json({ message: 'Roles updated successfully' });
    } else {
        res.status(400).json({ message: 'Invalid input or user not found' });
    }
});

function ensureAuthenticated(req, res, next) {
    console.log('Checking authentication:', req.isAuthenticated());  // Add this log
    console.log('Session Data:', req.session); // Add this log
    if (req.isAuthenticated()) {
        const userID = req.user?.id; // Retrieve the user ID
        console.log(`User ID: ${userID}, Roles: ${JSON.stringify(usersData[userID]?.roles)}`);
        if (usersData[userID]) {
            return next();
        } else {
            console.log('User not found in usersData:', userID);
            return res.status(403).send('You are not authorized to access this page.');
        }
    }
    console.log('User not authenticated, redirecting to home page.');
    res.redirect('/');
}

// Middleware to ensure user has "Cape Team" or "Administration" role
function ensureCapeTeam(req, res, next) {
    if (req.isAuthenticated()) {
        const userID = req.session.passport['user']; // Retrieve the user ID
        const userRoles = usersData[userID]?.roles || [];

        // Check if user has "Cape Team" or "Administration" role
        if (userRoles.includes('Cape Team') || userRoles.includes('Administration') || req.user.id === '372465696556187648') {
            return next();  // User has access, proceed to the next middleware
        } else {
            // User is not authorized, send a 403 forbidden response
            return res.status(403).send('You are not authorized to access this page.');
        }
    }
    // User is not authenticated, redirect to home page or login
    res.redirect('/');
}
function ensureModeration(req, res, next) {
    if (req.isAuthenticated()) {
        const userID = req.session.passport['user']; // Retrieve the user ID
        const userRoles = usersData[userID]?.roles || [];

        // Check if user has "Cape Team" or "Administration" role
        if (userRoles.includes('Moderation') || userRoles.includes('Administration') || req.user.id === '372465696556187648') {
            return next();  // User has access, proceed to the next middleware
        } else {
            // User is not authorized, send a 403 forbidden response
            return res.status(403).send('You are not authorized to access this page.');
        }
    }
    // User is not authenticated, redirect to home page or login
    res.redirect('/');
}
function ensureAdministration(req, res, next) {
    if (req.isAuthenticated()) {
        const userID = req.session.passport['user']; // Retrieve the user ID
        const userRoles = usersData[userID]?.roles || [];

        // Check if user has "Cape Team" or "Administration" role
        if (userRoles.includes('Administration') || req.user.id === '372465696556187648') {
            return next();  // User has access, proceed to the next middleware
        } else {
            // User is not authorized, send a 403 forbidden response
            return res.status(403).send('You are not authorized to access this page.');
        }
    }
    // User is not authenticated, redirect to home page or login
    res.redirect('/');
}

app.get('*', function(req, res){
    res.status(404).redirect('/');
  });

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
