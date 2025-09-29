import express, { Request, Response,NextFunction } from "express";
const app=express();
const port=process.env.PORT || 3000
import { PrismaClient } from "@/generated/prisma";
import { Prisma } from "./generated/prisma";
import cors from "cors"
const prisma=new PrismaClient()
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken";
import { sendPasswordResetOtp } from './emailService'; 
import crypto from 'crypto';
import multer from 'multer';
import path from 'path';
import { validate as uuidValidate } from 'uuid';
import { createClient } from 'redis';




app.use(express.json())
app.use(express.urlencoded({extended:true}))
app.use(cors());


const redisClient = createClient({
    // By default, it connects to redis://127.0.0.1:6379
    // For production, i'll use a URL from an environment variable:
});

redisClient.on('error', (err) => console.log('Redis Client Error', err));

(async () => {
    await redisClient.connect();
    console.log("Connected to Redis successfully!");
})();


// This tells TypeScript that our custom Request object can have a 'user' property.
declare global {
    namespace Express {
        export interface Request {
            user?: {
                userId: string;
                email: string;
                iat: number;
                exp: number;
                // Add the role property
                role?: 'USER' | 'ADMIN'; 
            };
        }
    }
}

// This middleware is updated to check the Redis blocklist.
const authenticateToken = async (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format is "Bearer TOKEN"

    if (token == null) {
        return res.status(401).json({ error: "Authentication token is required" });
    }

    try {
        // NEW: Check if the token is on the blocklist in Redis
        const isBlocked = await redisClient.get(`blocklist:${token}`);
        if (isBlocked) {
            return res.status(403).json({ error: "Token is invalid. Please log in again." });
        }

        // IMPORTANT: Replace "YOUR_SECRET_KEY" with a real secret from a .env file
        jwt.verify(token, "YOUR_SECRET_KEY", (err: any, user: any) => {
            if (err) {
                return res.status(403).json({ error: "Token is not valid" });
            }
            req.user = user; // Add the decoded token payload to the request
            next(); // Continue to the actual route handler
        });
    } catch (error) {
        console.error("Error during token authentication:", error);
        return res.status(500).json({ error: "Internal server error" });
    }
};



const authorizeAdmin = (req: Request, res: Response, next: NextFunction) => {
    // This function acts as a wrapper around the existing authentication middleware
    authenticateToken(req, res, () => {
        // If authentication is successful, then check for the admin role
        if (req.user?.role !== 'ADMIN') {
            return res.status(403).json({ error: "Forbidden: Access is restricted to administrators." });
        }
        // If the user is an admin, proceed to the actual route handler
        next();
    });
};






app.post("/api/auth/register", async (req: Request, res: Response) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ error: "Username, email, and password are required" })
        }

        // Checks for existing user by either email OR username in one query
        const existingUser = await prisma.user.findFirst({
            where: {
                OR: [
                    { email: email },
                    { username: username }
                ]
            }
        });

        // If a user was found, return a specific error message
        if (existingUser) {
            const message = existingUser.email === email
                ? "A user with this email already exists."
                : "This username is already taken.";
            return res.status(409).json({ error: message });
        }

        //else create a new user
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await prisma.user.create({
            data: { username, email, passwordHash: hashedPassword }
        })

        // Return a safe response with the newly created username, email, and id
        res.status(201).json({
            message: "Successfully created a new account.",
            user: { id: user.id, username: user.username, email: user.email }
        });

    } catch (error) {
        console.error("Registration Error:", error);
        res.status(500).json({ message: "Error while creating a new user" })
    }
});

app.post("/api/auth/login",async(req:Request,res:Response)=>{
   try {
    const { email, username, password } = req.body;

    // Basic validation to ensure an identifier (email or username) is provided.
    if (!(email || username)) {
        return res.status(400).json({ error: "Please provide an email or username." });
    }

   
    // This will find the first user that matches either the email OR the username.
    const user = await prisma.user.findFirst({
        where: {
            OR: [
                { email: email },
                { username: username },
            ],
        },
    });

    if (!user) {
        return res.status(401).json({ error: "Invalid credentials" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash ?? "");
    if (!isPasswordValid) {
        return res.status(401).json({ error: "Invalid credentials" });
    }

    // 
    const token = jwt.sign(
        { userId: user.id, email: user.email, role: user.role }, // You can add more user data to the payload if needed
        "YOUR_SECRET_KEY", 
        { expiresIn: '24h' }
    );

    res.json({ token });
} catch (error) {
    console.error(error);
    res.status(500).json({ error: "Login failed" });
}
})


// NEW: The /logout endpoint now uses the authentication middleware and has logic
app.post("/api/auth/logout", authenticateToken, async (req: Request, res: Response) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token || !req.user) {
            return res.status(401).json({ error: "Authentication error" });
        }

        // The 'exp' claim from the JWT is a Unix timestamp in seconds.
        const expirationTime = req.user.exp;
        const currentTime = Math.floor(Date.now() / 1000);

        // Calculate the remaining time until the token expires
        const expiresIn = expirationTime - currentTime;

        if (expiresIn > 0) {
            // Add the token to the Redis blocklist with its remaining time as the TTL
            await redisClient.set(`blocklist:${token}`, 'true', {
                EX: expiresIn
            });
        }
        
        res.status(200).json({ message: "Successfully logged out" });
    } catch (error) {
        console.error("Logout Error:", error);
        res.status(500).json({ error: "Logout failed" });
    }
});



app.post("/api/user/change-password", authenticateToken, async (req: Request, res: Response) => {
    try {
        const { oldPassword, newPassword } = req.body;
        if (!oldPassword || !newPassword) {
            return res.status(400).json({ error: "Old password and new password are required" });
        }

        const userId = req.user?.userId;
        if (!userId) {
            return res.status(401).json({ error: "Authentication error" });
        }

        const user = await prisma.user.findUnique({ where: { id: userId } });
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        const isPasswordValid = await bcrypt.compare(oldPassword, user.passwordHash ?? "");
        if (!isPasswordValid) {
            return res.status(401).json({ error: "Invalid old password" });
        }

        const newHashedPassword = await bcrypt.hash(newPassword, 10);
        await prisma.user.update({
            where: { id: userId },
            data: { passwordHash: newHashedPassword },
        });

        res.status(200).json({ message: "Password changed successfully" });

    } catch (error) {
        console.error("Change Password Error:", error);
        res.status(500).json({ error: "Failed to change password" });
    }
});




// Endpoint 1: User requests a password reset
app.post("/api/auth/request-password-reset", async (req: Request, res: Response) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ error: "Email is required" });
        }

        const user = await prisma.user.findUnique({ where: { email } });
        
        if (!user) {
            return res.status(200).json({ message: "If an account with this email exists, a password reset OTP has been sent." });
        }

        // Generate a 6-digit OTP
        const otp = crypto.randomInt(100000, 999999).toString();
        const hashedOtp = await bcrypt.hash(otp, 10);
        const expires = new Date(Date.now() + 10 * 60 * 1000); // OTP expires in 10 minutes

        // Invalidate any old password reset OTPs for this user
        await prisma.otp.updateMany({
            where: {
                userId: user.id,
                purpose: "RESET_PASSWORD"
            },
            data: {
                used: true
            }
        });

        // Store the new hashed OTP in the database using the generic Otp model
        await prisma.otp.create({
            data: {
                userId: user.id,
                otpCode: hashedOtp,
                expiresAt: expires,
                purpose: "RESET_PASSWORD", // Set the purpose
            }
        });

        // Send the plain OTP to the user's email
        await sendPasswordResetOtp(user.email, otp);

        res.status(200).json({ message: "If an account with this email exists, a password reset OTP has been sent." });

    } catch (error) {
        console.error("Request Password Reset Error:", error);
        res.status(500).json({ error: "Failed to request password reset" });
    }
});



// Endpoint 2: User provides the OTP and a new password
app.post("/api/auth/reset-password", async (req: Request, res: Response) => {
    try {
        const { email, otp, newPassword } = req.body;
        if (!email || !otp || !newPassword) {
            return res.status(400).json({ error: "Email, OTP, and new password are required" });
        }

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            return res.status(400).json({ error: "Invalid OTP or email" });
        }

        // Find the latest, valid, unused OTP for password reset
        const validOtp = await prisma.otp.findFirst({
            where: {
                userId: user.id,
                purpose: "RESET_PASSWORD",
                used: false,
                expiresAt: { gt: new Date() } // Check if the token has not expired
            },
            orderBy: { createdAt: 'desc' }
        });

        if (!validOtp) {
            return res.status(400).json({ error: "Invalid or expired OTP" });
        }

        // Compare the provided OTP with the stored hashed OTP
        const isOtpValid = await bcrypt.compare(otp, validOtp.otpCode);
        if (!isOtpValid) {
            return res.status(400).json({ error: "Invalid OTP or email" });
        }

        // Hash the new password and update the user
        const newHashedPassword = await bcrypt.hash(newPassword, 10);
        await prisma.user.update({
            where: { id: user.id },
            data: { passwordHash: newHashedPassword }
        });

        // Mark the OTP as used so it cannot be used again
        await prisma.otp.update({
            where: { id: validOtp.id },
            data: { used: true }
        });

        res.status(200).json({ message: "Password has been reset successfully." });

    } catch (error) {
        console.error("Reset Password Error:", error);
        res.status(500).json({ error: "Failed to reset password" });
    }
});


//user related endpoints


app.get("/api/users/me", authenticateToken, async (req: Request, res: Response) => {
    try {
        const userId = req.user?.userId;
        if (!userId) {
            // This case should ideally not be hit if authenticateToken is working
            return res.status(401).json({ error: "Authentication error" });
        }

        const userProfile = await prisma.user.findUnique({
            where: {
                id: userId,
            },
            select: {
                id: true,
                username: true,
                email: true,
                role: true,
                bio: true,
                profilePic: true,
                emailVerified: true,
                createdAt: true,
                _count: {
                    select: {
                        posts: true,
                        followers: true,
                        following: true,
                    },
                },
            },
        });

        if (!userProfile) {
            return res.status(404).json({ error: "User not found" });
        }
      
        const response = {
            id: userProfile.id,
            username: userProfile.username,
            email: userProfile.email,
            role: userProfile.role,
            bio: userProfile.bio,
            profilePic: userProfile.profilePic,
            emailVerified: userProfile.emailVerified,
            createdAt: userProfile.createdAt,
            postsCount: userProfile._count.posts,
            followersCount: userProfile._count.followers,
            followingCount: userProfile._count.following,
        };

        res.status(200).json(response);
    } catch (error) {
        console.error("Failed to fetch user profile:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});


//updating an user's details
app.patch("/api/users/me", authenticateToken, async (req: Request, res: Response) => {
    try {
        const userId = req.user?.userId;
        if (!userId) {
            return res.status(401).json({ error: "Authentication error" });
        }
        
        // 1. Get only the fields you want to allow updates for
        const { username, bio, profilePic } = req.body;

        // An empty request body is not an error, but nothing needs to be done
        if (username === undefined && bio === undefined && profilePic === undefined) {
             return res.status(400).json({ error: "Request body must contain at least one field to update (username, bio, profilePic)" });
        }

        // 2. Update the user in the database
        const updatedUser = await prisma.user.update({
            where: { id: userId },
            data: {
                username, // Prisma is smart and will ignore any fields that are undefined
                bio,
                profilePic,
            },
           
            select: {
                id: true,
                username: true,
                email: true,
                role: true,
                bio: true,
                profilePic: true,
            }
        });

        res.status(200).json(updatedUser);

    } catch (error) {
        if (error instanceof Prisma.PrismaClientKnownRequestError) {
            if (error.code === 'P2002') {
                return res.status(409).json({ error: "This username is already taken. Please choose another one." });
            }
        }
        
        // Generic catch-all for other errors
        console.error("Error while updating user details:", error);
        res.status(500).json({ message: "An error occurred while updating user details." });
    }
});

app.get("/api/users/:username", async (req: Request, res: Response) => {
    try {
        const { username } = req.params;

        // Fetch the user and their related counts from the database
        const userProfile = await prisma.user.findUnique({
            where: { username: username },
            // Select ONLY public-safe fields
            select: {
                id: true,
                username: true,
                bio: true,
                profilePic: true,
                createdAt: true, 
                _count: {
                    select: {
                        posts: true,
                        followers: true,
                        following: true,
                    },
                },
            },
        });

        // If no user is found, send a 404 Not Found response
        if (!userProfile) {
            return res.status(404).json({ error: "User not found" });
        }
        
        const response = {
            id: userProfile.id,
            username: userProfile.username,
            bio: userProfile.bio,
            profilePic: userProfile.profilePic,
            createdAt: userProfile.createdAt,
            postsCount: userProfile._count.posts,
            followersCount: userProfile._count.followers,
            followingCount: userProfile._count.following,
        };

        res.status(200).json(response);

    } catch (error) {
        console.error("Failed to fetch user profile:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get("/api/users/:username/posts", async (req: Request, res: Response) => {
    try {
        const { username } = req.params;

        // Pagination setup
        const page = parseInt(req.query.page as string) || 1;
        const pageSize = parseInt(req.query.pageSize as string) || 10;
        const skip = (page - 1) * pageSize;

        // First, find the user to get their ID, as posts are linked by ID
        const user = await prisma.user.findUnique({
            where: { username: username },
            select: { id: true } // We only need the ID for the next query
        });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        // Fetch the paginated posts for that user's ID
        const posts = await prisma.post.findMany({
            where: {
                authorId: user.id,
            },
            orderBy: {
                createdAt: 'desc',
            },
            take: pageSize,
            skip: skip,
        });
        
        // Get the total count of posts for pagination metadata
        const totalPosts = await prisma.post.count({
            where: {
                authorId: user.id,
            }
        });

        res.status(200).json({
            posts,
            currentPage: page,
            totalPages: Math.ceil(totalPosts / pageSize),
            totalPosts
        });

    } catch (error) {
        console.error("Failed to fetch user posts:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});



// --- Multer Configuration ---
// This sets up how and where Multer will store the uploaded files.
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); // The folder where files will be saved
    },
    filename: (req, file, cb) => {
        // Create a unique filename to prevent overwriting
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const fileFilter = (req: Request, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
    if (file.mimetype === 'image/jpeg' || file.mimetype === 'image/png' || file.mimetype === 'image/gif') {
        cb(null, true); // Accept file
    } else {
        cb(new Error('Invalid file type, only JPEG, PNG, and GIF is allowed!')); // Reject file
    }
};

const upload = multer({ storage: storage, fileFilter: fileFilter, limits: { fileSize: 1024 * 1024 * 5 } }); // Limit file size to 5MB

// --- The Endpoint ---
// 1. authenticateToken: Ensures the user is logged in.
// 2. upload.single('image'): Processes a single file upload from a field named 'image'.
app.post("/api/posts", authenticateToken, upload.single('image'), async (req: Request, res: Response) => {
    try {
        const userId = req.user?.userId;
        if (!userId) {
            return res.status(401).json({ error: "Authentication error" });
        }

        // Multer puts the file info in `req.file` and text fields in `req.body`
        const { caption } = req.body;
        const imageFile = req.file;

        // Validation
        if (!imageFile) {
            return res.status(400).json({ error: "Post image is required." });
        }
        if (!caption) {
            return res.status(400).json({ error: "Caption is required." });
        }
        
        // The path where the image was saved
        const imagePath = imageFile.path;

        // Create the post in the database
        const newPost = await prisma.post.create({
            data: {
                caption: caption,
                image: imagePath, // Store the path to the image
                authorId: userId
            }
        });

        // Use 201 Created for successful resource creation
        res.status(201).json(newPost);

    } catch (error) {
        // This will catch errors from Multer (e.g., file too large) as well
        console.error("Failed to create post:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});



//post for feed of the user
app.get("/api/posts", authenticateToken, async (req: Request, res: Response) => {
    try {
        const userId = req.user?.userId;
        if (!userId) {
            return res.status(401).json({ error: "Authentication error" });
        }

        // --- Pagination Logic ---
        const page = parseInt(req.query.page as string) || 1;
        const pageSize = parseInt(req.query.pageSize as string) || 10;
        const skip = (page - 1) * pageSize;

        // 1. Find all the users that the current user is following.
        const followingUsers = await prisma.follows.findMany({
            where: {
                followerId: userId,
            },
            select: {
                followingId: true, // We only need the IDs of the people they follow
            }
        });

        // 2. Extract the IDs into a simple array.
        const followedUserIds = followingUsers.map(follow => follow.followingId);
        
        // Pro Tip: To include the user's own posts in their feed, add their ID to the list.
        followedUserIds.push(userId);

        // 3. Fetch the posts from all the followed users.
        const posts = await prisma.post.findMany({
            where: {
                authorId: {
                    in: followedUserIds, // The 'in' operator is perfect for this
                }
            },
            orderBy: {
                createdAt: 'desc', // Show the newest posts first
            },
            take: pageSize,
            skip: skip,
            include: {
                // Include author details for each post
                author: {
                    select: {
                        username: true,
                        profilePic: true,
                    }
                },
            }
        });
        
        // 4. Get the total count for pagination metadata
        const totalPosts = await prisma.post.count({
            where: {
                authorId: {
                    in: followedUserIds,
                }
            }
        });

        res.status(200).json({
            posts,
            currentPage: page,
            totalPages: Math.ceil(totalPosts / pageSize),
            totalPosts,
        });

    } catch (error) {
        console.error("Failed to fetch feed:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});


//viewing a single post by its uuid
app.get("/api/posts/:postId", async (req: Request, res: Response) => {
    try {
        const { postId } = req.params;

        // 1. (Optional but Recommended) Validate that the postId is a valid UUID
        if (!uuidValidate(postId)) {
            return res.status(400).json({ error: "Invalid Post ID format." });
        }

        // 2. Fetch the post from the database
        const post = await prisma.post.findUnique({
            where: {
                id: postId,
            },
            // 3. Include related data needed for the post view
            include: {
                author: {
                    // Get the author's public information
                    select: {
                        id: true,
                        username: true,
                        profilePic: true,
                    },
                },
                // Get the most recent comments for the post
                Comment: {
                    take: 10, // Limit to the 10 most recent comments
                    orderBy: {
                        createdAt: 'desc',
                    },
                    include: {
                        // For each comment, also get its author's info
                        author: {
                            select: {
                                id: true,
                                username: true,
                                profilePic: true,
                            }
                        }
                    }
                }
            },
        });

        // 4. If no post is found with that ID, return a 404 error
        if (!post) {
            return res.status(404).json({ error: "Post not found" });
        }

        // 5. Send the detailed post object in the response
        res.status(200).json(post);

    } catch (error) {
        console.error("Failed to fetch post:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

//for updating a single post
app.patch("/api/posts/:postId", authenticateToken, async (req: Request, res: Response) => {
    try {
        const { postId } = req.params;
        const userId = req.user?.userId;

        if (!userId) {
            return res.status(401).json({ error: "Authentication error" });
        }

        // 1. Validate the Post ID format
        if (!uuidValidate(postId)) {
            return res.status(400).json({ error: "Invalid Post ID format." });
        }

        const { caption } = req.body;

        // 2. Validate that a caption was provided for the update
        if (typeof caption !== 'string') {
            return res.status(400).json({ error: "A new caption is required." });
        }

        // 3. Perform the update in one atomic and secure operation
        const updatedPost = await prisma.post.update({
            where: {
                // This compound 'where' ensures we only update the post if BOTH the ID matches
                // AND the authorId matches the currently logged-in user.
                id: postId,
                authorId: userId,
            },
            data: {
                caption: caption,
            },
        });

        res.status(200).json(updatedPost);

    } catch (error) {
        // 4. Handle specific errors from Prisma
        if (error instanceof Prisma.PrismaClientKnownRequestError) {
            // P2025 is the error code for "Record to update not found."
            // This elegantly handles both cases: the post doesn't exist, OR the user doesn't own it.
            if (error.code === 'P2025') {
                return res.status(404).json({ error: "Post not found or you do not have permission to edit it." });
            }
        }
        
        console.error("Failed to update post:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});



//deleting a single post by its id
app.delete("/api/posts/:postId", authenticateToken, async (req: Request, res: Response) => {
    try {
        const { postId } = req.params;
        const userId = req.user?.userId;

        if (!userId) {
            return res.status(401).json({ error: "Authentication error" });
        }

        // 1. Validate the Post ID format
        if (!uuidValidate(postId)) {
            return res.status(400).json({ error: "Invalid Post ID format." });
        }

        // 2. Perform the deletion in one atomic and secure operation
        await prisma.post.delete({
            where: {
                // This compound 'where' ensures we only delete the post if BOTH the ID matches
                // AND the authorId matches the currently logged-in user.
                id: postId,
                authorId: userId,
            },
        });

        // 3. Send a 204 No Content response for a successful deletion
        res.status(204).send();

    } catch (error) {
        // 4. Handle specific errors from Prisma
        if (error instanceof Prisma.PrismaClientKnownRequestError) {
            // P2025 is the error code for "Record to delete not found."
            // This handles both "post doesn't exist" and "user doesn't own the post".
            if (error.code === 'P2025') {
                return res.status(404).json({ error: "Post not found or you do not have permission to delete it." });
            }
        }
        
        console.error("Failed to delete post:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});



//endpoints that will handle like in a specific post
app.post("/api/posts/:postId/like", authenticateToken, async (req: Request, res: Response) => {
    try {
        const { postId } = req.params;
        const userId = req.user?.userId;

        if (!userId) {
            return res.status(401).json({ error: "Authentication error" });
        }

        // 1. Validate the Post ID format
        if (!uuidValidate(postId)) {
            return res.status(400).json({ error: "Invalid Post ID format." });
        }

        // 2. Use a Prisma transaction to ensure data consistency
        await prisma.$transaction(async (tx) => {
            // First, ensure the post actually exists
            const post = await tx.post.findUnique({
                where: { id: postId },
            });

            if (!post) {
                // By throwing an error inside a transaction, we cause it to roll back.
                throw new Error("Post not found");
            }
            
            // Attempt to create a 'Like' record.
            // This will fail if the user has already liked the post due to the unique constraint.
            await tx.like.create({
                data: {
                    postId: postId,
                    userId: userId,
                },
            });

            // If the like was created successfully, increment the post's likesCount
            await tx.post.update({
                where: { id: postId },
                data: {
                    likesCount: {
                        increment: 1, // Use Prisma's atomic increment operation
                    },
                },
            });
        });

        res.status(201).json({ message: "Post liked successfully" });

    } catch (error) {
        // 3. Handle specific errors, especially for duplicate likes
        if (error instanceof Prisma.PrismaClientKnownRequestError) {
            // P2002 is the error code for a unique constraint violation
            if (error.code === 'P2002') {
                return res.status(409).json({ error: "You have already liked this post." });
            }
        }
        
        // Handle the custom "Post not found" error from our transaction
        if (error instanceof Error && error.message === "Post not found") {
            return res.status(404).json({ error: "Post not found." });
        }

        console.error("Failed to like post:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

//endpoint to handle dislike in a post
app.delete("/api/posts/:postId/like", authenticateToken, async (req: Request, res: Response) => {
    try {
        const { postId } = req.params;
        const userId = req.user?.userId;

        if (!userId) {
            return res.status(401).json({ error: "Authentication error" });
        }

        // 1. Validate the Post ID format
        if (!uuidValidate(postId)) {
            return res.status(400).json({ error: "Invalid Post ID format." });
        }

        // 2. Use a Prisma transaction to ensure data consistency
        await prisma.$transaction(async (tx) => {
            // Attempt to delete the 'Like' record.
            // This will fail if the user hasn't liked the post.
            await tx.like.delete({
                where: {
                    // This special 'where' syntax targets the compound unique key
                    userId_postId: {
                        userId: userId,
                        postId: postId,
                    },
                },
            });

            // If the like was deleted successfully, decrement the post's likesCount
            await tx.post.update({
                where: { id: postId },
                data: {
                    likesCount: {
                        decrement: 1, // Use Prisma's atomic decrement operation
                    },
                },
            });
        });

        // 3. Send a 204 No Content response for a successful deletion
        res.status(204).send();

    } catch (error) {
        // 4. Handle the specific error for when the 'Like' record doesn't exist
        if (error instanceof Prisma.PrismaClientKnownRequestError) {
            // P2025 is "Record to delete not found."
            // This means the user tried to unlike a post they hadn't liked.
            if (error.code === 'P2025') {
                return res.status(404).json({ error: "You have not liked this post." });
            }
        }
        
        console.error("Failed to unlike post:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});


//endpoints for hadling the comments in the post
app.post("/api/posts/:postId/comments", authenticateToken, async (req: Request, res: Response) => {
    try {
        const { postId } = req.params;
        const userId = req.user?.userId;

        if (!userId) {
            return res.status(401).json({ error: "Authentication error" });
        }

        // 1. Validate the Post ID format
        if (!uuidValidate(postId)) {
            return res.status(400).json({ error: "Invalid Post ID format." });
        }

        const { text } = req.body;

        // 2. Validate that the comment text is not empty
        if (!text || typeof text !== 'string' || text.trim() === '') {
            return res.status(400).json({ error: "Comment text cannot be empty." });
        }

        // 3. Use a transaction to create the comment and update the post's comment count
        const newComment = await prisma.$transaction(async (tx) => {
            // First, ensure the post exists
            const post = await tx.post.findUnique({ where: { id: postId } });
            if (!post) {
                throw new Error("Post not found");
            }

            // Create the new comment
            const createdComment = await tx.comment.create({
                data: {
                    text: text.trim(),
                    postId: postId,
                    authorId: userId,
                },
                // Include the author's details in the response
                include: {
                    author: {
                        select: {
                            id: true,
                            username: true,
                            profilePic: true,
                        }
                    }
                }
            });

            // Atomically increment the commentsCount on the post
            await tx.post.update({
                where: { id: postId },
                data: {
                    commentsCount: {
                        increment: 1,
                    },
                },
            });

            return createdComment;
        });

        // 4. Send a 201 Created response with the new comment data
        res.status(201).json(newComment);

    } catch (error) {
        // 5. Handle specific errors, like a non-existent post
        if (error instanceof Error && error.message === "Post not found") {
            return res.status(404).json({ error: "Post not found." });
        }

        console.error("Failed to add comment:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});



app.get("/api/posts/:postId/comments", async (req: Request, res: Response) => {
    try {
        const { postId } = req.params;

        // 1. Validate the Post ID format
        if (!uuidValidate(postId)) {
            return res.status(400).json({ error: "Invalid Post ID format." });
        }

        // --- Pagination Logic ---
        const page = parseInt(req.query.page as string) || 1;
        const pageSize = parseInt(req.query.pageSize as string) || 15; // A larger page size might be suitable for comments
        const skip = (page - 1) * pageSize;

        // 2. (Optional but good practice) Check if the post actually exists
        const post = await prisma.post.findUnique({
            where: { id: postId },
        });

        if (!post) {
            return res.status(404).json({ error: "Post not found" });
        }

        // 3. Fetch the paginated comments for the given post
        const comments = await prisma.comment.findMany({
            where: {
                postId: postId,
            },
            orderBy: {
                createdAt: 'desc', // Show the newest comments first
            },
            take: pageSize,
            skip: skip,
            include: {
                // For each comment, include the author's public info
                author: {
                    select: {
                        id: true,
                        username: true,
                        profilePic: true,
                    },
                },
            },
        });

        // 4. Get the total count of comments for pagination metadata
        const totalComments = await prisma.comment.count({
            where: {
                postId: postId,
            },
        });

        res.status(200).json({
            comments,
            currentPage: page,
            totalPages: Math.ceil(totalComments / pageSize),
            totalComments,
        });

    } catch (error) {
        console.error("Failed to fetch comments:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});



app.delete("/api/comments/:commentId", authenticateToken, async (req: Request, res: Response) => {
    try {
        const { commentId } = req.params;
        const userId = req.user?.userId; // The ID of the user trying to delete the comment

        if (!userId) {
            return res.status(401).json({ error: "Authentication error" });
        }

        // 1. Validate the Comment ID format
        if (!uuidValidate(commentId)) {
            return res.status(400).json({ error: "Invalid Comment ID format." });
        }

        // 2. Use a transaction to handle the complex authorization and deletion logic
        await prisma.$transaction(async (tx) => {
            // First, find the comment and its post's author ID
            const comment = await tx.comment.findUnique({
                where: { id: commentId },
                select: {
                    authorId: true, // The ID of the person who wrote the comment
                    post: {
                        select: {
                            id: true,
                            authorId: true // The ID of the person who owns the post
                        }
                    }
                }
            });

            // If the comment doesn't exist, throw an error
            if (!comment) {
                throw new Error("Comment not found");
            }

            // 3. Authorization Check:
            // The user is NOT the comment's author AND they are NOT the post's author
            if (userId !== comment.authorId && userId !== comment.post.authorId) {
                throw new Error("Forbidden"); // Throw a specific error for authorization failure
            }

            // If the check passes, proceed with the deletion and counter update
            
            // Decrement the post's commentsCount
            await tx.post.update({
                where: { id: comment.post.id },
                data: {
                    commentsCount: {
                        decrement: 1,
                    },
                },
            });

            // Delete the actual comment
            await tx.comment.delete({
                where: { id: commentId },
            });
        });

        // 4. Send a 204 No Content response for a successful deletion
        res.status(204).send();

    } catch (error) {
        // 5. Handle the custom errors thrown from within the transaction
        if (error instanceof Error) {
            if (error.message === "Comment not found") {
                return res.status(404).json({ error: "Comment not found." });
            }
            if (error.message === "Forbidden") {
                return res.status(403).json({ error: "You do not have permission to delete this comment." });
            }
        }
        
        console.error("Failed to delete comment:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});


//endpoints for handling the follow-following
app.post("/api/users/:userId/follow", authenticateToken, async (req: Request, res: Response) => {
    try {
        // The user performing the action (the follower)
        const followerId = req.user?.userId;
        // The user to be followed
        const followingId = req.params.userId;

        if (!followerId) {
            return res.status(401).json({ error: "Authentication error" });
        }

        // 1. Validate the ID of the user to be followed
        if (!uuidValidate(followingId)) {
            return res.status(400).json({ error: "Invalid User ID format." });
        }

        // 2. Prevent a user from following themselves
        if (followerId === followingId) {
            return res.status(400).json({ error: "You cannot follow yourself." });
        }

        // 3. Check if the user to be followed actually exists
        const userToFollow = await prisma.user.findUnique({
            where: { id: followingId }
        });
        if (!userToFollow) {
            return res.status(404).json({ error: "User not found." });
        }
        
        // 4. Create the 'Follows' relationship
        await prisma.follows.create({
            data: {
                followerId: followerId,
                followingId: followingId,
            }
        });
        
        res.status(201).json({ message: `You are now following ${userToFollow.username}` });

    } catch (error) {
        // 5. Handle the case where the user is already following the target user
        if (error instanceof Prisma.PrismaClientKnownRequestError) {
            // P2002 is the error code for a unique constraint violation
            if (error.code === 'P2002') {
                return res.status(409).json({ error: "You are already following this user." });
            }
        }

        console.error("Failed to follow user:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});


//for unfollow
app.delete("/api/users/:userId/follow", authenticateToken, async (req: Request, res: Response) => {
    try {
        // The user performing the action (the follower)
        const followerId = req.user?.userId;
        // The user to be unfollowed
        const followingId = req.params.userId;

        if (!followerId) {
            return res.status(401).json({ error: "Authentication error" });
        }

        // 1. Validate the ID of the user to be unfollowed
        if (!uuidValidate(followingId)) {
            return res.status(400).json({ error: "Invalid User ID format." });
        }
        
        // 2. Delete the 'Follows' relationship
        await prisma.follows.delete({
            where: {
                // This special 'where' syntax targets the compound unique key
                followerId_followingId: {
                    followerId: followerId,
                    followingId: followingId,
                },
            },
        });
        
        // 3. Send a 204 No Content response for a successful deletion
        res.status(204).send();

    } catch (error) {
        // 4. Handle the case where the user wasn't following the target user
        if (error instanceof Prisma.PrismaClientKnownRequestError) {
            // P2025 is "Record to delete not found."
            if (error.code === 'P2025') {
                return res.status(404).json({ error: "You are not following this user." });
            }
        }

        console.error("Failed to unfollow user:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});


app.get("/api/users/:userId/followers", async (req: Request, res: Response) => {
    try {
        const { userId } = req.params;

        // 1. Validate the User ID format
        if (!uuidValidate(userId)) {
            return res.status(400).json({ error: "Invalid User ID format." });
        }

        // --- Pagination Logic ---
        const page = parseInt(req.query.page as string) || 1;
        const pageSize = parseInt(req.query.pageSize as string) || 20;
        const skip = (page - 1) * pageSize;

        // 2. (Optional but good practice) Check if the user exists
        const user = await prisma.user.findUnique({ where: { id: userId } });
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        // 3. Fetch the 'Follows' records where the user is the one being followed
        const followsRecords = await prisma.follows.findMany({
            where: {
                followingId: userId,
            },
            orderBy: {
                createdAt: 'desc', // Show the most recent followers first
            },
            take: pageSize,
            skip: skip,
            // 4. Select only the public profile of the follower
            select: {
                follower: {
                    select: {
                        id: true,
                        username: true,
                        bio: true,
                        profilePic: true,
                    }
                }
            }
        });

        // 5. Get the total follower count for pagination
        const totalFollowers = await prisma.follows.count({
            where: {
                followingId: userId,
            },
        });
        
        // 6. Transform the data to a cleaner list of user profiles
        const followers = followsRecords.map(record => record.follower);

        res.status(200).json({
            followers,
            currentPage: page,
            totalPages: Math.ceil(totalFollowers / pageSize),
            totalFollowers,
        });

    } catch (error) {
        console.error("Failed to fetch followers:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

//following
app.get("/api/users/:userId/following", async (req: Request, res: Response) => {
    try {
        const { userId } = req.params;

        // 1. Validate the User ID format
        if (!uuidValidate(userId)) {
            return res.status(400).json({ error: "Invalid User ID format." });
        }

        // --- Pagination Logic ---
        const page = parseInt(req.query.page as string) || 1;
        const pageSize = parseInt(req.query.pageSize as string) || 20;
        const skip = (page - 1) * pageSize;

        // 2. (Optional but good practice) Check if the user actually exists
        const user = await prisma.user.findUnique({ where: { id: userId } });
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        // 3. Fetch the records from the 'Follows' table
        const followRecords = await prisma.follows.findMany({
            where: {
                followerId: userId, // Find where the specified user is the one doing the following
            },
            select: {
                // From those records, select the full profile of the user being followed
                following: {
                    select: {
                        id: true,
                        username: true,
                        profilePic: true,
                        bio: true,
                    }
                }
            },
            orderBy: {
                createdAt: 'desc', // Show the most recently followed users first
            },
            take: pageSize,
            skip: skip,
        });

        // 4. Get the total count for pagination metadata
        const totalFollowing = await prisma.follows.count({
            where: {
                followerId: userId,
            },
        });
        
        // 5. Transform the data to get a clean array of user profiles
        const following = followRecords.map(record => record.following);

        res.status(200).json({
            following,
            currentPage: page,
            totalPages: Math.ceil(totalFollowing / pageSize),
            totalFollowing,
        });

    } catch (error) {
        console.error("Failed to fetch following list:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});



//All the admin endpoints
app.get("/api/admin/users", authorizeAdmin, async (req: Request, res: Response) => {
    try {
        // --- Pagination Logic ---
        const page = parseInt(req.query.page as string) || 1;
        const pageSize = parseInt(req.query.pageSize as string) || 25;
        const skip = (page - 1) * pageSize;

        // Fetch all users with pagination
        const users = await prisma.user.findMany({
            orderBy: {
                createdAt: 'desc',
            },
            take: pageSize,
            skip: skip,
            // Select fields appropriate for an admin view.
            // CRITICAL: Never include the passwordHash.
            select: {
                id: true,
                username: true,
                email: true,
                role: true,
                isActive: true,
                emailVerified: true,
                createdAt: true,
                lastLogin: true,
            }
        });

        const totalUsers = await prisma.user.count();

        res.status(200).json({
            users,
            currentPage: page,
            totalPages: Math.ceil(totalUsers / pageSize),
            totalUsers,
        });

    } catch (error) {
        console.error("Failed to fetch users for admin:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});


//deactivate or delete a user
app.delete("/api/admin/users/:userId", authorizeAdmin, async (req: Request, res: Response) => {
    try {
        const adminId = req.user?.userId;
        const userIdToDelete = req.params.userId;
        const { mode } = req.query; // e.g., ?mode=hard

        // 1. Validate the User ID format
        if (!uuidValidate(userIdToDelete)) {
            return res.status(400).json({ error: "Invalid User ID format." });
        }
        
        // 2. Prevent an admin from deleting their own account
        if (adminId === userIdToDelete) {
            return res.status(400).json({ error: "Administrators cannot delete their own accounts." });
        }

        if (mode === 'hard') {
            // --- HARD DELETE ---
            // This is a destructive and irreversible action.
            await prisma.user.delete({
                where: { id: userIdToDelete },
            });
            
        } else {
            // --- SOFT DELETE (Default and Recommended) ---
            // Use a transaction to deactivate the user and revoke their sessions.
            await prisma.$transaction(async (tx) => {
                // Set the user's account to inactive
                await tx.user.update({
                    where: { id: userIdToDelete },
                    data: { isActive: false },
                });
                // Revoke all of the user's refresh tokens to log them out of active sessions
                await tx.refreshToken.updateMany({
                    where: { userId: userIdToDelete },
                    data: { revoked: true },
                });
            });
        }
        
        // 3. Send a 204 No Content response for a successful operation
        res.status(204).send();

    } catch (error) {
        // 4. Handle cases where the user to delete does not exist
        if (error instanceof Prisma.PrismaClientKnownRequestError) {
            // P2025 is "Record to delete/update not found."
            if (error.code === 'P2025') {
                return res.status(404).json({ error: "User not found." });
            }
        }

        console.error("Failed to delete/deactivate user:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});


//for deleting any post 
app.delete("/api/admin/posts/:postId", authorizeAdmin, async (req: Request, res: Response) => {
    try {
        const { postId } = req.params;

        // 1. Validate the Post ID format
        if (!uuidValidate(postId)) {
            return res.status(400).json({ error: "Invalid Post ID format." });
        }

        // 2. Delete the post from the database without checking for ownership
        await prisma.post.delete({
            where: {
                id: postId,
            },
        });
        
        // 3. Send a 204 No Content response for a successful deletion
        res.status(204).send();

    } catch (error) {
        // 4. Handle cases where the post to delete does not exist
        if (error instanceof Prisma.PrismaClientKnownRequestError) {
            // P2025 is "Record to delete not found."
            if (error.code === 'P2025') {
                return res.status(404).json({ error: "Post not found." });
            }
        }

        console.error("Failed to delete post (admin):", error);
        res.status(500).json({ error: "Internal server error" });
    }
});


//for deleting any comment
app.delete("/api/admin/comments/:commentId", authorizeAdmin, async (req: Request, res: Response) => {
    try {
        const { commentId } = req.params;

        // 1. Validate the Comment ID format
        if (!uuidValidate(commentId)) {
            return res.status(400).json({ error: "Invalid Comment ID format." });
        }

        // 2. Use a transaction to ensure data consistency
        await prisma.$transaction(async (tx) => {
            // First, find the comment to get its postId for the counter update
            const comment = await tx.comment.findUnique({
                where: { id: commentId },
                select: { postId: true } // We only need the postId
            });

            // If the comment doesn't exist, throw an error to abort the transaction
            if (!comment) {
                throw new Error("Comment not found");
            }

            // Decrement the commentsCount on the parent post
            await tx.post.update({
                where: { id: comment.postId },
                data: {
                    commentsCount: {
                        decrement: 1,
                    },
                },
            });
            
            // Finally, delete the comment itself
            await tx.comment.delete({
                where: { id: commentId },
            });
        });

        // 3. Send a 204 No Content response for a successful deletion
        res.status(204).send();

    } catch (error) {
        // 4. Handle specific errors, like a comment that doesn't exist
        if (error instanceof Error && error.message === "Comment not found") {
            return res.status(404).json({ error: "Comment not found." });
        }

        console.error("Failed to delete comment (admin):", error);
        res.status(500).json({ error: "Internal server error" });
    }
});


app.listen(port,()=>{
    console.log(`Server is running on port ${port}`)
})