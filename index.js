const express = require('express');
const app = express();
const dotenv = require('dotenv');
const mongoose = require('mongoose');

//import routes
const authRoute = require('./routes/auth');

dotenv.config();

//connect to db
mongoose.connect(
    process.env.DB_CONNECT,
    { useNewUrlParser: true, 
        useUnifiedTopology: true }, () => {
            console.log('Connected to db!');
        }
);

//middleware
app.use(express.json());

//route middlewares
app.use('/api/user', authRoute);

app.listen(3000, () => console.log('Server up and running...'));