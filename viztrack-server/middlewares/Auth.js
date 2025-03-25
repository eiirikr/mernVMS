const AdminRegistrationModel = require("../models/AdminModel");
const jwt = require('jsonwebtoken');

const auth = async (req, res, next) => {
    let token;

    // Check if token is in the Authorization header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            // Extract token from header
            token = req.headers.authorization.split(' ')[1];

            // Verify the token
            const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

            // Find the admin by decoded user_id and exclude password
            req.admin = await AdminRegistrationModel.findById(decoded.user_id).select('-password');

            // If admin not found, return an error
            if (!req.admin) {
                return res.status(404).json({ message: 'Admin not found' });
            }

            // Continue to the next middleware or route handler
            next();

        } catch (e) {
            console.error(e);
            return res.status(401).json({ message: "Auth Failed, Wrong Token" });
        }
    }

    // If no token is found
    if (!token) {
        return res.status(401).json({ message: "Auth Failed, Token Not Found" });
    }
};

module.exports = { auth };
