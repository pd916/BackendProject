import {asyncHandler} from '../utils/AsyncHandler.js'
import {ApiError} from '../utils/ApiError.js'
import {User} from '../modals/User.model.js'
import {uploadOnCloudinary} from '../utils/cloudinary.js'
import { ApiResponse } from '../utils/ApiResponse.js'
import { Jwt } from 'jsonwebtoken'


const generateAccessAndRefereshTokens = async(userId) => {
      try {
         const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refereshToken = user.generateRefreshToken()

        user.refereshToken = refereshToken
        await user.save({validateBeforeSave: false})

        return {accessToken, refereshToken}

      } catch (error) {
         throw new ApiError(500, "Something went wrong while generating refersh and access token")
      }
}


const registerUser = asyncHandler(async(req, res)=> {
   const {fullName, email, username, password} = req.body
//    console.log("email :", email)

   if (
    [fullName, email, username, password].some((field)=> field?.trim() === "")
   ) {
      throw new ApiError(400, "All fields are required")
   }

   const existedUser = await User.findOne({
    $or: [{ username }, { email } ]
   })

   if(existedUser) {
    throw new ApiError(409, "User with email or username already exist")
   }

   console.log(req.files)

   const avatarLocalPath = req.files?.avatar[0]?.path
//    const coverImageLocalPath = req.files?.coverImage[0]?.path

   let coverImageLocalPath;
   if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
    coverImageLocalPath = req.files.coverImage[0].path
   }

   if(!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is required")
   }

   const avatar = await uploadOnCloudinary(avatarLocalPath)
   const coverImage = await uploadOnCloudinary(coverImageLocalPath)

   if(!avatar) {
    throw new ApiError(400, "Avatar file is required")
   }

   const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase()
   })

   const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
   )

   if(!createdUser) {
    throw new ApiError(500, "something went wrong while registedring the user")
   }

   return res.status(201).json(
    new ApiResponse(200, createdUser, "User register Successfully")
   )
})

const loginUser = asyncHandler(async ( req, res)=> {
   //req body -> data
   //usernaem or email
   //find the user
   //password check
   //access  and referesh token
   //send cookies

   const {username, email, password} = req.body

   if(!username && !email) {
      throw new ApiError(400, "username or email is required")
   }

   const user = await User.findOne({
      $or: [{username}, {email}]
   })

   if(!user) {
      throw new ApiError(404, "User does not exist")
   }

   const isPasswordValid = await user.isPasswordCorrect(password)

   if(!isPasswordValid) {
      throw new ApiError(401, "Invalid user credentials")
   }

   const {accessToken, refreshToken} = await generateAccessAndRefereshTokens(user._id)

   const loggedInUser = await User.findById(user._id).select("-password, -refreshToken")

   const options = {
      httpOnly: true,
      secure: true
   }

   return res
   .status(200)
   .cookie("accessToken", accessToken, options)
   .cookie("refreshToken", refreshToken, options)
   .json(
      new ApiResponse(
         200,
         {
            user: loggedInUser, accessToken, refreshToken
         },
         "User logged In Successfully"
      )
   )

})


const logoutUser = asyncHandler(async (req, res)=> {
  await User.findByIdAndUpdate(
      req.user._id,
      {
         $set: {
            refreshToken: undefined
         }
      },
      {
         new: true
      }
   )

   const options = {
      httpOnly: true,
      secure: true
   }

   return res.status(200).clearCookie("accessToken", options).clearCookie("refreshToken", options)
   .json(new ApiResponse(200, {}, "User logged Out"))

})

const refreshAccessToken = asyncHandler(async (req, res)=> {
   const incomingRefreshToken = req.cookies.refereshToken || req.body.refereshToken

   if(incomingRefreshToken) {
      throw new ApiError(401, "unauthorized request")
   }

   try {
      const decodedToken  = Jwt.verify(
         incomingRefreshToken,
         process.env.REFRESH_TOKEN_SECRET
      )
   
      const user = await User.findById(decodedToken?._id)
   
      if(!user) {
         throw new ApiError(401, "Invalid refreshToken")
      }
      
      if(incomingRefreshToken !== user?.refreshToken)
      throw new ApiError(401, "Refresh Token is expired or used")
   
      const options = {
         httpOnly: true,
         secure: true
      }
   
      const {accessToken, newRefereshToken} = await generateAccessAndRefereshTokens(user._id)
   
      return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefereshToken, options)
      .json (
         new ApiResponse(
            200,
            {accessToken, refreshToken:newRefereshToken},
            "access toke  refreshed"
         )
      )
   } catch (error) {
      throw new ApiError(401, error?.message || "invalid refresh Token")
   }
})


export {registerUser, loginUser, logoutUser, refreshAccessToken}