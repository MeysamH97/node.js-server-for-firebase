require('dotenv').config();

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const admin = require('firebase-admin');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

console.log('Starting server...');

// Initialize Firebase Admin SDK
const serviceAccount = require('./streamed-chat-firebase-adminsdk-nrhxl-23e6fed2c0.json'); // Firebase Admin SDK JSON file path
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore(); // Or use admin.database() for Realtime Database

const app = express();
const server = http.createServer(app);

const SECRET_KEY = process.env.SECRET_KEY; // استفاده از متغیر محیطی

app.use(cors());
app.use(express.json()); // To parse JSON bodies

const io = socketIo(server, {
  cors: {
    origin: '*', // Allow all origins (you can restrict this to specific domains if needed)
    methods: ['GET', 'POST']
  }
});


// اضافه کردن یک مجموعه برای مدیریت توکن‌ها
const tokensCollection = db.collection('activeTokens');

// Function to add a token to the active tokens list
async function addToken(userId, token) {
  await tokensCollection.doc(userId).set({ token });
}

// Function to check if a token is valid
async function isTokenValid(userId, token) {
  const doc = await tokensCollection.doc(userId).get();
  return doc.exists && doc.data().token === token;
}

// Function to remove a token from the active tokens list
async function removeToken(userId) {
  await tokensCollection.doc(userId).delete();
}

// Endpoint for user login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Fetch user data from Firestore
    const userSnapshot = await admin.firestore().collection('users').where('email', '==', email).get();
    
    if (userSnapshot.empty) {
      return res.status(401).json({ error: 'Invalid email' });
    }

    const userDoc = userSnapshot.docs[0];
    const userData = userDoc.data();
    
    // Verify password using bcrypt
    const passwordMatch = await bcrypt.compare(password, userData.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: userData.id }, SECRET_KEY, { expiresIn: '1h' });
    await addToken(userData.id, token);  // Store token in the database

    res.status(200).json({ userData, token }); // Return user data along with token
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(401).json({ error: 'Failed to log in' });
  }
});

// Endpoint for user sign out
app.post('/signout', async (req, res) => {
  const { userId } = req.body;

  try {
    // Remove the token from the active tokens list
    await removeToken(userId);

    res.status(200).json({ message: 'User signed out successfully' });
  } catch (error) {
    console.error('Error signing out:', error);
    res.status(400).json({ error: 'Failed to sign out' });
  }
});

// Endpoint for check user token
app.get('/checkToken', verifyToken, (req, res) => {
  res.status(200).json({ message: 'Token is valid' });
});

// Middleware to verify token
async function verifyToken(req, res, next) {
  const token = req.body['token'];
  const userId = req.body['userId'];

  if (!token || !userId) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const isValid = await isTokenValid(userId, token);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    jwt.verify(token, SECRET_KEY); // Verify the token
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(401).json({ error: 'Failed to authenticate token' });
  }
}

// Endpoint for user registration
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Create user in Firebase Authentication
    const hashedPassword = await bcrypt.hash(password, 10); // Hash the password
    const userRecord = await admin.auth().createUser({ email, password: hashedPassword });

    // Store additional user data in Firestore
    userData = {
      'id': userRecord.uid,
      'email': email,
      'username': null,
      'profilePictureUrl': null,
      'isOnline': true,
      'blockedUsers': [],
      'contacts': [],
      'password': hashedPassword, // Store hashed password
    };

    await admin.firestore().collection('users').doc(userRecord.uid).set(userData);

    res.status(200).json(userData);
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(400).json({ error: 'Failed to register user' });
  }
});


// Endpoint for updating user data
app.put('/updateUser', async (req, res) => {
  const { userId, updates } = req.body;

  try {
    // Update user data in Firestore
    await admin.firestore().collection('users').doc(userId).update(updates);

    // Fetch updated user data
    const userDoc = await admin.firestore().collection('users').doc(userId).get();
    const updatedUserData = userDoc.exists ? userDoc.data() : {};

    res.status(200).json(updatedUserData);
  } catch (error) {
    console.error('Error updating user data:', error);
    res.status(400).json({ error: 'Failed to update user data' });
  }
});

// Listen for client connections
io.on('connection', (socket) => {
  console.log('New client connected');

  // Handle fetching data for a specific user
  socket.on('fetchUserData', async (userId) => {
    console.log('Received message:', userId); // Print received message
    console.log(`Fetching data from collection: Users, document: ${userId}`);
    try {
      const docRef = db.collection('users').doc(userId);
      const doc = await docRef.get(); // Fetch specific document from Firestore
      if (doc.exists) {
        console.log('userDataFetched', doc.data());
        console.log('Send data back to the client');
        socket.emit('userDataFetched', doc.data()); // Send data back to the client
      } else {
        console.log('No such document!');
        socket.emit('error', 'No such document!');
      }
    } catch (error) {
      console.error('Error fetching userData:', error);
      socket.emit('error', 'Failed to fetch userData');
    }
  });

  // Firestore listener for changes in a specific document
  socket.on('watchDocument', (userId) => {
    const docRef = db.collection('users').doc(userId);
    const unsubscribe = docRef.onSnapshot((doc) => {
      if (doc.exists) {
        socket.emit('documentChanged', doc.data());
      } else {
        socket.emit('error', 'No such document!');
      }
    });

    // Clean up listener on disconnect
    socket.on('disconnect', () => {
      console.log('Client disconnected');
      unsubscribe();
    });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
