import { User } from "../modals/User.model.js";
import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/AsyncHandler.js";
import Jwt  from "jsonwebtoken";



export const verifyJWT = asyncHandler(async (req, _, nex) => {
  try {
     const token = req.cookies?.accessToken || req.header ("Authorization")?.replace("Bearer ", "")
  
     if(!token) {
      throw new ApiError(401, "Unauthorized request")
     }
  
     const decodedToken = Jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
  
     const user = await User.findById(decodedToken?._id).select("-password -refreshToken")
  
     if(!user) {
      //Todo: discuss about frontend
      throw new ApiError(401, "Invalid Access Token" )
     }
  
     req.user = user;
     nex()
  } catch (error) {
    throw new ApiError(401, error?.message || "Invalid access token")
  }
})