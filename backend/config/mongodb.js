import mongoose from "mongoose";


const connectDB = async () => {
    try {
        // Mongoose ka event listener hai
        mongoose.connection.on('connected', () => {
            console.log(`Database is Connected Successfully.`)
        })
        await mongoose.connect(`${process.env.MONGODB_URI}/MERN_AUTHENTICATION`)
    } catch (error) {
        console.log(`An Error Occured During Database Connection ${error}.`)
    }
}

export default connectDB