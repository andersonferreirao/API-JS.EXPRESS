const mongoose = require('mongoose');

const User = mongoose.model("User",{
    name: String,
    email: String,
    password: String,
    phone: String,
    address: String,
    city: String,
    birthdate: String
});

module.exports = User;
