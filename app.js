require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const path = require('path');
const fs = require('fs');
const app = express();
const PORT = 3000;

const adminUserID = '372465696556187648';  // Replace with the actual admin user ID
const usersDataFile = path.join(__dirname, 'usersData.json');

// Load users data from JSON file
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


let availableRoles = [
    'Cape Team', 'Cape Head', 'Customer Support', 
    'Support Head', 'Moderation', 'Moderation Administration', 'Administration'
];


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
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// After initializing the session
app.use((req, res, next) => {
    console.log('Session:', req.session); // Log the session data
    next();
});


// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// Define the scopes that will be requested from Discord
const scopes = ['identify'];

// Configure the Discord OAuth strategy
let users = {};  // In-memory storage for user profiles

// Configure the Discord OAuth strategy
passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: process.env.DISCORD_CALLBACK_URL,
    scope: scopes
},
(accessToken, refreshToken, profile, done) => {
    // Check if the user's Discord ID exists in usersData
    if (!usersData[profile.id]) {
        // If user is not found in the allowed users list, block the login
        return done(null, false, { message: 'You are not authorized to log in.' });
    }

    // Save the user profile information if they are authorized
    users[profile.id] = {
        id: profile.id,
        username: profile.username,
        avatar: profile.avatar,  // User avatar hash
        discriminator: profile.discriminator  // User discriminator (e.g. #1234)
    };
    
    return done(null, profile);
}));



// Serialize user into the session
passport.serializeUser((user, done) => {
    console.log('Serializing user:', user);  // Log user being serialized
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    const userData = usersData[id];
    if (userData) {
        done(null, { id, roles: userData.roles, nickname: userData.nickname });
    } else {
        done(new Error('User not found'));
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/terms', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'terms.html'));
});
app.get('/privacy', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
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
app.get('/discord', (req, res) => {
    res.redirect('https://discord.gg/9zk4umeHcD');
  });
  
app.get('/api/user', ensureAuthenticated, (req, res) => {
    res.json({ username: req.user.nickname || 'Guest' }); // Send user data
});
// In your '/api/user/roles' endpoint, log the userID and roles
app.get('/api/user/roles', ensureAuthenticated, (req, res) => {
    console.log('Fetching roles for user:', req.user.id); // Log user ID
    const userID = req.user.id;
    const roles = usersData[userID]?.roles || [];
    console.log('Roles found:', roles); // Log roles found
    res.json({ roles });  // Send the user's roles as a JSON response
});




// Logout route
app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error('Error logging out:', err);
        }
        res.redirect('/');
    });
});

// Discord OAuth login route
app.get('/auth/discord', (req, res, next) => {
    if (req.isAuthenticated()) {
        return res.redirect('/staff');  // Redirect if already logged in
    }
    next();
}, passport.authenticate('discord'));

// Discord OAuth callback route
app.get('/auth/discord/callback',
    passport.authenticate('discord', { failureRedirect: '/' }),
    (req, res) => {
        console.log('User logged in:', req.user);  // Log user data
        res.redirect('/staff');
    }
);

// Middleware to ensure the user is authenticated
function ensureAuthenticated(req, res, next) {
    console.log('Authenticated:', req.isAuthenticated());
    console.log('Session:', req.session);  // Log the entire session object
    console.log('User:', req.user);  // Log the user object
    if (req.isAuthenticated()) {
        const userID = req.user.id;

        // Check if the authenticated user exists in the usersData
        if (usersData[userID]) {
            console.log('User found in usersData:', usersData[userID]);
            return next();  // User is allowed, proceed to the next middleware
        } else {
            console.error('User not authorized:', userID);
            return res.status(403).json({ message: 'You are not authorized to access this page.' });
        }
    }
    // User is not authenticated, send a 401 unauthorized response
    console.error('User not authenticated');
    return res.status(401).json({ message: 'Unauthorized' }); // Change to JSON response
}





// Admin route to manage permissions and display user profiles
app.get('/admin', ensureAdministration, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Routes to get all users and roles (admin only)
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

// Middleware to ensure user has "Cape Team" or "Administration" role
function ensureCapeTeam(req, res, next) {
    if (req.isAuthenticated()) {
        const userID = req.user.id;
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
        const userID = req.user.id;
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
        const userID = req.user.id;
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
    console.log(`Server is running on ${PORT}`);
    console.log('Loaded users data:', usersData);

});
