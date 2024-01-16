import {asyncHandler} from '../utils/AsyncHandler.js'
import {ApiError} from '../utils/ApiError.js'
import {User} from '../modals/User.model.js'
import {uploadOnCloudinary} from '../utils/cloudinary.js'
import { ApiResponse } from '../utils/ApiResponse.js'
import { Jwt } from 'jsonwebtoken'
import mongoose from 'mongoose'


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

   if(!incomingRefreshToken) {
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

const changeCurrentPassword = asyncHandler(async(req, res)=> {
   const {oldPassword, newPassword} = req.body

   const user = await User.findById(req.user?._id)
   const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

   if(!isPasswordCorrect){
      throw new ApiError(401, "Invalid old password")
   }

   user.password = newPassword
   await user.save({validateBeforeSave: false})

   return res
   .status(200)
   .json(new ApiResponse(200, {}, "password changed successfully"))
})

const getCurrentUser = asyncHandler(async(req, res)=> {
   return res
   .status(200)
   .json(200, req.user, "current user fetched successfully")
})

const updateAccountDetails = asyncHandler(async(req, res)=>{
   const {fullName, email} = req.body

   if(!fullName || !email){
      throw new ApiError(400, "All fields are required")
   }

   const user = await User.findByIdAndUpdate(
      req.user?._id,
      {
         $set: {
            fullName,
            email: email
         }
      },
      {new: true}
      ).select("-password")

      return res
      .status(200)
      .json(new ApiResponse(200, user, "Account details updated successfully"))
})

const updateUserAvatar = asyncHandler(async(req, res)=> {
   const avatarLocalPath = req.file?.path

   if(!avatarLocalPath){
      throw new ApiError(400, "Avatar file is missing")
   }

   const  avatar = await uploadOnCloudinary(avatarLocalPath)

   if(!avatar.url){
      throw new ApiError(400, "Error while uploading on avatar")
   }

   const user = await User.findByIdAndUpdate(
      req.user?._id,
      {
         $set: {
            avatar: avatar.url
         }
      },
      {new: true}
   ).select("-password")

   return res
   .status(200)
   .json(
      new ApiResponse(200, user, "Avatar Image updated successfully")
   )
})

const updateUserCoverImage = asyncHandler(async(req, res)=> {
   const coverImageLocalPath = req.file?.path

   if(!coverImageLocalPath){
      throw new ApiError(400, "Cover Image file is missing")
   }

   const  coverImage = await uploadOnCloudinary(coverImageLocalPath)

   if(!coverImage.url){
      throw new ApiError(400, "Error while uploading on avatar")
   }

   const user = await User.findByIdAndUpdate(
      req.user?._id,
      {
         $set: {
            coverImage: coverImage.url
         }
      },
      {new: true}
   ).select("-password")

   return res
   .status(200)
   .json(
      new ApiResponse(200, user, "cover Image updated successfully")
   )
})

const getUserChannelProfile = asyncHandler(async(req, res) => {
   const {username} = req.params

   if(!username?.trim()){
      throw new ApiError(400, "username is missing")
   }

   const channel = await User.aggregate([
      {
         $match: {
            username: username?.toLowerCase()
         }
      },
      {
         $lookup: {
            from: "subscriptions",
            localField: "_id",
            foreignField: "channel",
            as: "subscribers"
         }
      },
      {
         $lookup: {
            from: "subscriptions",
            localField: "_id",
            foreignField: "subscriber",
            as: "subscribedTo"
         }
      },
      {
         $addFields: {
            subscribersCount: {
               $size: "$subscribers"
            },
            channelsSubscribedToCount: {
               $size: "$subscribedTo"
            },
            isSubscribed: {
               $cond: {
                  if: {$in: [req.user?._id, "$subscribers.subscribers"]},
                  then: true,
                  else: false
               }
            }
         }
      },
      {
         $project: {
            fullName: 1,
            username: 1,
            subscribersCount: 1,
            channelsSubscribedToCount: 1,
            isSubscribed: 1,
            avatar: 1,
            coverImage: 1,
            email: 1
         }
      }
   ])

   if(!channel?.length){
      throw new ApiError(404, "channel does not exist")
   }

   return res 
   .status(200)
   .json(
      new ApiResponse(200, channel[0], "User channel fetched successfully")
   )
})

const getWatchHistory = asyncHandler(async(req, res) => {
   const user = await User.aggregate([
      {
         $match:{
            _id: new mongoose.Types.ObjectId(req.user._id)
         }
      },
      {
         $lookup: {
            from: "videos",
            localField: "watchHistory",
            foreignField: "_id",
            as: "watchHistory",
            pipeline: [
               {
                  $lookup:{
                     from: "users",
                     localField: "owner",
                     foreignField: "_id",
                     as: "owner",
                     pipeline: [
                        {
                           $project: {
                              fullName: 1,
                              username: 1,
                              avatar: 1
                           }
                        }
                     ]
                  }
               },
               {
                  $addFields: {
                     owner:{
                        $first:"$owner"
                     }
                  }
               }
            ]
         }
      }
   ])

   return res
   .status(200)
   .json(
      new ApiResponse(
         200,
         user[0].watchHistory,
         "Watch History Fetched Successfully"
      )
   )
})

export {
   registerUser,
    loginUser,
     logoutUser, 
     refreshAccessToken,
     changeCurrentPassword,
     getCurrentUser,
     updateAccountDetails,
     updateUserAvatar,
     updateUserCoverImage,
     getUserChannelProfile,
     getWatchHistory
   }