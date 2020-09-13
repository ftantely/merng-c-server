const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const {UserInputError} = require('apollo-server')


const {validateRegisterInput} = require('../../util/validators')
const {validateLoginInput} = require('../../util/validators')
const {SECRET_KEY} =require('../../config')
const User = require('../../models/User')

module.exports = {
    Mutation: {
        async login(_, {username, password}){
            const {valid, errors} = validateLoginInput(username, password);
            if(!valid){
                throw new UserInputError('Errors', {errors})
            }
            const user = await User.findOne({username});
            if(!user){
                errors.general = 'User not found';
                throw new UserInputError('User not found', {errors})
            }
            const match = await bcrypt.compare(password, user.password);
            if(!match){
                errors.general = 'Wrong credentials';
                throw new UserInputError('Wrong credentials', {errors})
            }
            const token = jwt.sign(
                {
                    id:user.id,
                    username: user.username,
                    email: user.email
                },
                SECRET_KEY,
                {expiresIn: '1h'}
            );
            return {
                ...user._doc,
                id:user._id,
                token
            }
        },
        async register(_,
                 {
                     registerInput: {
                         username, email, password, confirmPassword}
                 }){
            //Validate user
            const {valid, errors} = validateRegisterInput(username, email, password, confirmPassword);
            if(!valid){
                throw new UserInputError('Errors', {errors})
            }

            //Make sure username doesn't already exist
            const user = await User.findOne({username});
            if(user){
                throw new UserInputError('Username is already taken', {errors:{
                    username:'This username is already taken'
                    }})
            }
            // Hash password
            password = await bcrypt.hash(password, 12)
            const newUser = new User({
                username,
                email,
                password,
                creartedAt: new Date().toISOString()
            });
            const res = await newUser.save();
            const token = jwt.sign(
                {
                    id: res.id,
                    username: res.username,
                    email: res.email
                },
                SECRET_KEY,
                {expiresIn: '1h'}
            );
            return {
                ...res._doc,
                id: res._id,
                token
            }

        }
    }
}