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
    const data = userDoc.data();
    
    // Verify password using bcrypt
    const passwordMatch = await bcrypt.compare(password, data.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: data.id }, SECRET_KEY, { expiresIn: '1h' });
    await addToken(data.id, token);  // Store token in the database

    res.status(200).json({ data, token }); // Return user data along with token
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

  const token = req.headers['authorization']; 
  const userId = req.body['userId'];

  const tokenWithoutBearer = token.startsWith('Bearer ') ? token.slice(7) : token;

  if (!token || !userId) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const isValid = await isTokenValid(userId, tokenWithoutBearer);

    if (!isValid) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    jwt.verify(tokenWithoutBearer, SECRET_KEY); // Verify the token
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
    const data = {
      'id': userRecord.uid,
      'email': email,
      'username': null,
      'profilePictureUrl': null,
      'isOnline': true,
      'blockedUsers': [],
      'contacts': [],
      'password': hashedPassword, // Store hashed password
    };

    await admin.firestore().collection('users').doc(userRecord.uid).set(data);
    // Generate JWT token
    const token = jwt.sign({ userId: data.id }, SECRET_KEY, { expiresIn: '1h' });
    await addToken(data.id, token);  // Store token in the database

    res.status(200).json({ data, token }); // Return user data along with token
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(400).json({ error: 'Failed to register user' });
  }
});

// Endpoint to get user data by userId
app.get('/getUser/:userId', verifyToken, async (req, res) => {
  const { userId } = req.params;

  try {
    // Fetch user data from Firestore
    const userDoc = await db.collection('users').doc(userId).get();
    const data = userDoc.data();

    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json(data);
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).json({ error: 'Failed to fetch user data' });
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
    const data = userDoc.exists ? userDoc.data() : {};

    res.status(200).json(data);
  } catch (error) {
    console.error('Error updating user data:', error);
    res.status(400).json({ error: 'Failed to update user data' });
  }
});

// Listen for client connections
io.on('connection', (socket) => {
  console.log('New client connected');


  // Firestore listener for changes in a specific document
  socket.on('watchCurrentUserData', (userId) => {
    console.log(`Listening for changes to user: ${userId}`);
    const docRef = db.collection('users').doc(userId);
    const unsubscribe = docRef.onSnapshot((doc) => {
      if (doc.exists) {
        socket.emit(`currentUserDataChanged_${userId}`, doc.data());
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

  socket.on('watchOtherUserData', (contactId) => {
    console.log(`Listening for changes to contact: ${contactId}`);
    const docRef = db.collection('users').doc(contactId);
    
    const unsubscribe = docRef.onSnapshot((doc) => {
      if (doc.exists) {
        socket.emit(`otherUserDataChanged_${contactId}`, doc.data()); // ارسال داده‌ها با یک نام یکتا
      } else {
        socket.emit(`error_${contactId}`, 'No such document!');
      }
    });
  
    // Clean up listener on disconnect or when switching contacts
    socket.on('disconnect', () => {
      console.log(`Stopped listening to changes for contact: ${contactId}`);
      unsubscribe();
    });
  });

  // متد ایجاد چت
  socket.on('createChat', async ({ userId, chatId, title, admins, members, type }) => {
    try {
      // از تابع createChat استفاده کنید
      const generatedChatId = await createChat(userId, chatId, title, admins, members, type);
      
      // ارسال نتیجه موفقیت‌آمیز به کلاینت
      socket.emit(`chatCreated_${userId}`, { success: true, chatId: generatedChatId });
    } catch (error) {
      console.error('Error creating chat:', error);
      socket.emit('chatCreated', { success: false, error: error.message });
    }
  });

  // Firestore listener for changes in chat data
  socket.on('watchChatData', ({ userId, chatId }) => {
    console.log(`Listening for chat data changes for user: ${userId}, chat: ${chatId}`);
    const docRef =db.collection('users').doc(userId).collection('chats').doc(chatId);
    const unsubscribe = docRef.onSnapshot((doc) => {
      if (doc.exists) {
        socket.emit(`chatDataChanged_${userId}_${chatId}`, doc.data());
      } else {
        socket.emit(`error`, 'No such chat!');
      }
    });

    // Clean up listener on disconnect
    socket.on('disconnect', () => {
      console.log(`Stopped listening to changes for chat: ${chatId}`);
      unsubscribe();
    });
  });

// متد ایجاد چت
const createChat = async (userId, chatId, title, admins, members, type) => {
  try {
    const generatedChatId = chatId || db.collection('chats').doc().id;

    const chatData = {
      id: generatedChatId,
      title: title,
      owner: userId,
      admins: admins,
      members: members,
      messages: [],
      isTypings: [],
      type: type,
    };

    const chatRef = db.collection('users').doc(userId).collection('chats').doc(generatedChatId);
    await chatRef.set(chatData);

    const memberUpdates = members.map(async (memberId) => {
      const userChatRef = db.collection('users').doc(memberId).collection('chats');
      return userChatRef.doc(generatedChatId).set(chatData);
    });

    await Promise.all(memberUpdates);
    
    return generatedChatId; // برگرداندن ID چت ایجاد شده
  } catch (error) {
    console.error('Error creating chat:', error);
    throw new Error(error.message);
  }
};

// ایجاد پیام در یک چت
socket.on('sendMessage', async ({ userId, chatId, message }) => {
  try {
    const chatRef = db.collection('users').doc(userId).collection('chats').doc(chatId);
    const chatDoc = await chatRef.get();

    // اگر چت وجود ندارد، آن را ایجاد کنید
    if (!chatDoc.exists) {
      const users = chatId.split('_');
      const generatedChatId = await createChat(userId, chatId, '', [users[0],users[1]], [users[0],users[1]], 'private');
      console.log(`Chat created with ID: ${generatedChatId}`);
    }

    const messagesRef = chatRef.collection('messages').doc();

    const messageData = {
      id: messagesRef.id,
      sender: message['sender'],
      content: message['content'],
      time: message['time'] , // استفاده از Timestamp تبدیل شده
      type: message['type'],
    };

    await messagesRef.set(messageData);
    await chatRef.update({
      messages: admin.firestore.FieldValue.arrayUnion(messagesRef.id),
      lastMessage: messageData.id,
    });

    socket.emit(`messageSent_${userId}_${chatId}`, { success: true, messageId: messagesRef.id });
  } catch (error) {
    console.error('Error sending message:', error);
    socket.emit('messageSent', { success: false, error: error.message });
  }
});


  // Firestore listener for changes in message data
  socket.on('watchMessageData', ({ userId, chatId, messageId }) => {
    console.log(`Listening for message data changes for user: ${userId}, chat: ${chatId}, message: ${messageId}`);
    const docRef = db.collection('users').doc(userId).collection('chats').doc(chatId).collection('messages').doc(messageId);
    const unsubscribe = docRef.onSnapshot((doc) => {
      if (doc.exists) {
        const messageData = doc.data();
        socket.emit(`messageDataChanged_${userId}_${chatId}_${messageId}`, messageData);
      } else {
        socket.emit('error', 'No such message!');
      }
    });

    // Clean up listener on disconnect
    socket.on('disconnect', () => {
      console.log(`Stopped listening to changes for message: ${messageId}`);
      unsubscribe();
    });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
