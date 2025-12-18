const express = require("express");
const cors = require("cors");
const app = express();
require("dotenv").config();

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const stripe = require("stripe")(process.env.PAYMENT_GATEWAY_API_KEY);

const port = process.env.Port || 3000;

const admin = require("firebase-admin");

const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf8"
);
const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const crypto = require("crypto");
const { log, error } = require("console");

function generateTrackingId() {
  const prefix = "PKG";
  const date = new Date().toISOString().split("T")[0].replace(/-/g, "");
  const randomHex = crypto.randomBytes(4).toString("hex").toUpperCase();

  return `${prefix}-${date}-${randomHex}`;
}

// middelware
app.use(express.json());
app.use(cors());

//verify FB Token
const verifyFBToken = async (req, res, next) => {
  const token = req.headers?.authorization;
  // console.log(token);
  if (!token) {
    return res
      .status(401)
      .send({ error: true, message: "unauthorized Access" });
  }
  try {
    const idToken = token.split(" ")[1];
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    // console.log('decoded',decodedToken);
    req.decoded_email = decodedToken.email;
  } catch (error) {
    // console.log('token error',error);
    return res
      .status(401)
      .send({ error: true, message: "unauthorized access" });
  }

  next();
};

const uri =`mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.btpwoe8.mongodb.net/?appName=Cluster0`

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

app.get("/", (req, res) => {
  res.send("Chef bazzer server run successfully");
});

async function run() {
  try {
    // await client.connect();

    const db = client.db("chefDB");
    const usersCollections = db.collection("users");
    const mealsCollections = db.collection("meals");
    const reviewsCollection = db.collection("reviews");
    const favoritesCollection = db.collection("favorites");
    const orderCollection = db.collection("orders");
    const paymentCollections = db.collection("payments");
    const trackingsCollections = db.collection("trackings");
    const chefsCollection = db.collection("chefs");

    //middleware admin before allowing admin activity
    //must be used after verifyFBToken middleware
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded_email;
      const query = { email };
      const user = await usersCollections.findOne(query);
      if (!user || user.role !== "admin") {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };

    //verify for chef
    const verifyChef = async (req, res, next) => {
      const email = req.decoded_email;
      const query = { email };
      const user = await usersCollections.findOne(query);
      if (!user || user.role !== "chef") {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };

    //tracking middle ware
    const logTracking = async (trackingId, status) => {
      const log = {
        trackingId,
        status,
        details: status.split("_").join(" "),
        createdAt: new Date(),
      };
      const result = await trackingsCollections.insertOne(log);
      return result;
    };

    //this api for admin when he search a user
    app.get("/users", verifyFBToken, async (req, res) => {
      const search = req.query.search;
      const query = {};
      if (search) {
        query.$or = [
          { name: { $regex: search, $options: "i" } },
          { email: { $regex: search, $options: "i" } },
        ];
      }
      const cursor = usersCollections
        .find(query)
        .sort({ createdAt: -1 })
        .limit(20);
      const result = await cursor.toArray();
      res.send(result);
    });

    //get the role base users
    app.get("/users/:email/role", async (req, res) => {
      try {
        const { email } = req.params;
        if (!email) {
          return res.status(400).json({
            success: false,
            message: "Email parameter is required",
          });
        }

        const user = await usersCollections.findOne({ email });
        if (!user) {
          return res.status(404).json({
            success: false,
            message: "User not found",
            role: "user",
          });
        }
        return res.status(200).json({
          success: true,
          role: user.role || "user",
          status: user.status || "active",
          chefId: user.chefId || null,
          address: user.address,
        });
      } catch (error) {
        console.error("Error fetching user role:", error);

        return res.status(500).json({
          success: false,
          message: "Internal server error",
        });
      }
    });

    //login users
    app.post("/users", async (req, res) => {
      const user = req.body;
      user.role = "user";
      user.status = "active";
      user.createdAt = new Date();
      const query = { email: user?.email };

      const existingUser = await usersCollections.findOne(query);
      if (existingUser) {
        return res.send({ message: "user already exists" });
      }

      const result = await usersCollections.insertOne(user);
      res.send(result);
    });

    app.patch(
      "/users/:id/role",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const roleInfo = req.body;
        const query = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            role: roleInfo.role,
          },
        };
        const result = await usersCollections.updateOne(query, updateDoc);

        res.send(result);
      }
    );

    // Update user status (fraud/active)
    app.patch(
      "/users/:id/status",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const id = req.params.id;
          const { status } = req.body;
          const query = { _id: new ObjectId(id) };
          const updateDoc = {
            $set: {
              status: status,
            },
          };
          const result = await usersCollections.updateOne(query, updateDoc);
          res.send(result);
        } catch (error) {
          console.error("Error updating user status:", error);
          res
            .status(500)
            .send({ error: true, message: "Failed to update status" });
        }
      }
    );

    //get the all meals with search and pagination
    app.get("/meals", async (req, res) => {
      try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 9;
        const search = req.query.search || "";

        const query = {
          $or: [{ ChefName: { $regex: search, $options: "i" } }],
        };

        const total = await mealsCollections.countDocuments(query);
        const result = await mealsCollections
          .find(query)
          .skip((page - 1) * limit)
          .limit(limit)
          .toArray();

        res.send({
          meals: result,
          total,
          totalPages: Math.ceil(total / limit),
          currentPage: page,
        });
      } catch (error) {
        console.error("Error fetching meals:", error);
        res.status(500).send({ message: "Error fetching meals" });
      }
    });

    //get meals details
    app.get("/meals-details/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await mealsCollections.findOne(query);
      res.send(result);
    });

    // Get meals by chef ID
    app.get("/meals/chef/:chefId", async (req, res) => {
      try {
        const chefId = req.params.chefId;
        const query = { ChefId: chefId };
        const result = await mealsCollections.find(query).toArray();
        res.send(result);
      } catch (error) {
        console.error("Error fetching chef meals:", error);
        res.status(500).send({ error: true, message: "Failed to fetch meals" });
      }
    });

    // Create new meal
    app.post("/meals", async (req, res) => {
      try {
        const mealData = req.body;
        const result = await mealsCollections.insertOne(mealData);
        res.send(result);
      } catch (error) {
        console.error("Error creating meal:", error);
        res.status(500).send({ error: true, message: "Failed to create meal" });
      }
    });

    // Update meal
    app.patch("/meals/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const mealData = req.body;
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: mealData,
        };
        const result = await mealsCollections.updateOne(filter, updateDoc);
        res.send(result);
      } catch (error) {
        console.error("Error updating meal:", error);
        res.status(500).send({ error: true, message: "Failed to update meal" });
      }
    });

    // Delete meal
    app.delete("/meals/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const filter = { _id: new ObjectId(id) };
        const result = await mealsCollections.deleteOne(filter);
        res.send(result);
      } catch (error) {
        console.error("Error deleting meal:", error);
        res.status(500).send({ error: true, message: "Failed to delete meal" });
      }
    });

    // Reviews APIs
    app.get("/reviews/:foodId", async (req, res) => {
      const foodId = req.params.foodId;
      const query = { foodId: foodId };
      const result = await reviewsCollection.find(query).toArray();
      res.send(result);
    });

    app.post("/reviews", async (req, res) => {
      const review = req.body;
      const result = await reviewsCollection.insertOne(review);
      res.send(result);
    });

    app.get("/reviews", async (req, res) => {
      const email = req.query.email;
      let query = {};
      if (email) {
        query = { email: email };
      }
      const result = await reviewsCollection.find(query).toArray();
      res.send(result);
    });

    app.delete("/reviews/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await reviewsCollection.deleteOne(query);
      res.send(result);
    });

    app.patch("/reviews/:id", async (req, res) => {
      const id = req.params.id;
      const { rating, comment } = req.body;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          rating: rating,
          comment: comment,
        },
      };
      const result = await reviewsCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // Favorites APIs
    app.post("/favorites", async (req, res) => {
      const favorite = req.body;
      const query = {
        userEmail: favorite.userEmail,
        mealId: favorite.mealId,
      };
      const existingFavorite = await favoritesCollection.findOne(query);
      if (existingFavorite) {
        return res.send({ message: "Already in favorites", insertedId: null });
      }
      const result = await favoritesCollection.insertOne(favorite);
      res.send(result);
    });

    app.get("/favorites/:email", async (req, res) => {
      const email = req.params.email;
      const query = { userEmail: email };
      const result = await favoritesCollection.find(query).toArray();
      res.send(result);
    });

    // Check if partial favorite
    app.get("/favorites/:email/:mealId", async (req, res) => {
      const { email, mealId } = req.params;
      const query = { userEmail: email, mealId: mealId };
      const result = await favoritesCollection.findOne(query);
      res.send({ isFavorite: !!result, _id: result?._id });
    });

    // Delete favorite
    app.delete("/favorites/:email/:mealId", async (req, res) => {
      const { email, mealId } = req.params;
      const query = { userEmail: email, mealId: mealId };
      const result = await favoritesCollection.deleteOne(query);
      res.send(result);
    });

    // Order API

    app.get("/orders", async (req, res) => {
      const query = {};
      const { email, orderStatus } = req.query;

      if (email) {
        query.userEmail = email;
      }

      if (orderStatus) {
        query.orderStatus = orderStatus;
      }

      const options = {
        sort: { createdAt: -1 },
      };

      try {
        const cursor = orderCollection.find(query, options);
        const result = await cursor.toArray();
        res.send(result);
      } catch (error) {
        console.error("Error fetching orders:", error);
        res.status(500).send({ message: "Error fetching orders" });
      }
    });

    app.post("/orders", async (req, res) => {
      const order = req.body;
      const trackingId = generateTrackingId();

      // Set initial order status and payment status
      order.createdAt = new Date();
      order.trackingId = trackingId;
      order.orderStatus = "pending-chef-approval";
      order.paymentStatus = "unpaid";

      logTracking(trackingId, "order_requested");

      const result = await orderCollection.insertOne(order);
      res.send(result);
    });

    app.delete("/orders/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await orderCollection.deleteOne(query);
      res.send(result);
    });

    // Chef accept order endpoint
    app.patch(
      "/orders/:id/accept",

      async (req, res) => {
        try {
          const id = req.params.id;
          const filter = { _id: new ObjectId(id) };
          const order = await orderCollection.findOne(filter);
          if (!order) {
            return res
              .status(404)
              .send({ error: true, message: "Order not found" });
          }

          if (order.orderStatus !== "pending-chef-approval") {
            return res
              .status(400)
              .send({ error: true, message: "Order is not pending approval" });
          }

          const updateDoc = {
            $set: {
              orderStatus: "accepted-by-chef",
              acceptedAt: new Date(),
            },
          };

          const result = await orderCollection.updateOne(filter, updateDoc);
          await logTracking(order.trackingId, "chef_accepted");

          res.send(result);
        } catch (error) {
          console.error("Error accepting order:", error);
          res
            .status(500)
            .send({ error: true, message: "Failed to accept order" });
        }
      }
    );

    // Chef cancel order endpoint
    app.patch(
      "/orders/:id/cancel",

      async (req, res) => {
        try {
          const id = req.params.id;
          const filter = { _id: new ObjectId(id) };

          const order = await orderCollection.findOne(filter);
          if (!order) {
            return res
              .status(404)
              .send({ error: true, message: "Order not found" });
          }

          const updateDoc = {
            $set: {
              orderStatus: "cancelled",
              cancelledAt: new Date(),
            },
          };

          const result = await orderCollection.updateOne(filter, updateDoc);
          await logTracking(order.trackingId, "order_cancelled");

          res.send(result);
        } catch (error) {
          console.error("Error cancelling order:", error);
          res
            .status(500)
            .send({ error: true, message: "Failed to cancel order" });
        }
      }
    );

    // Chef deliver order endpoint
    app.patch(
      "/orders/:id/deliver",

      async (req, res) => {
        try {
          const id = req.params.id;
          const filter = { _id: new ObjectId(id) };

          const order = await orderCollection.findOne(filter);
          if (!order) {
            return res
              .status(404)
              .send({ error: true, message: "Order not found" });
          }

          if (
            order.orderStatus !== "accepted-by-chef" &&
            order.orderStatus !== "pending-pickup"
          ) {
            return res.status(400).send({
              error: true,
              message: "Order must be accepted before delivery",
            });
          }

          const updateDoc = {
            $set: {
              orderStatus: "delivered",
              deliveredAt: new Date(),
            },
          };

          const result = await orderCollection.updateOne(filter, updateDoc);
          await logTracking(order.trackingId, "order_delivered");

          res.send(result);
        } catch (error) {
          console.error("Error delivering order:", error);
          res
            .status(500)
            .send({ error: true, message: "Failed to mark as delivered" });
        }
      }
    );
    //payment api

    app.post("/create-checkout-session", async (req, res) => {
      const paymentInfo = req.body;
    
      const amount = Math.round(parseFloat(paymentInfo.price) * 100);

      try {
        const session = await stripe.checkout.sessions.create({
          line_items: [
            {
              price_data: {
                currency: "USD",
                product_data: {
                  name: `Order Payment for ${paymentInfo.mealName}`,
                },
                unit_amount: amount,
              },
              quantity: 1,
            },
          ],
          mode: "payment",
          customer_email: paymentInfo.userEmail,
          metadata: {
            orderId: paymentInfo.orderId,
            foodName: paymentInfo.foodName,
            mealName: paymentInfo.mealName,
            trackingId: paymentInfo.trackingId,
            userName: paymentInfo.userName,
            userEmail: paymentInfo.userEmail,
          },
          success_url: `${process.env.SITE_DOMAIN}/dashboard`,
          cancel_url: `${process.env.SITE_DOMAIN}/dashboard`,
        });

        res.send({ url: session.url });
      } catch (error) {
        console.error("Stripe session creation error:", error);
        res
          .status(500)
          .send({ error: true, message: "Failed to create checkout session" });
      }
    });

    //payment success status update
    app.patch("/payment-success", async (req, res) => {
      const sessionId = req.query.session_id;
   

      try {
        const session = await stripe.checkout.sessions.retrieve(sessionId);
  
        const transactionId = session.payment_intent;

        const query = { transactionId: transactionId };
        const existingPayment = await paymentCollections.findOne(query);

        if (existingPayment) {
  
          return res.send({
            success: true,
            message: "Payment already processed",
            transactionId,
            trackingId: existingPayment.trackingId,
          });
        }

        const trackingId = session.metadata.trackingId;
        const orderId = session.metadata.orderId;

        if (session.payment_status === "paid") {
          if (!ObjectId.isValid(orderId)) {
            console.error("Invalid Order ID from metadata:", orderId);
            return res
              .status(400)
              .send({ error: true, message: "Invalid Order ID" });
          }

          const filter = { _id: new ObjectId(orderId) };

          // Verify order is accepted by chef before processing payment
          const order = await orderCollection.findOne(filter);
          if (!order) {
            return res
              .status(404)
              .send({ error: true, message: "Order not found" });
          }

          if (order.orderStatus !== "accepted-by-chef") {
            return res.status(400).send({
              error: true,
              message: "Order must be accepted by chef before payment",
            });
          }

          const update = {
            $set: {
              paymentStatus: "paid",
              orderStatus: "pending-pickup",
            },
          };

          const updateResult = await orderCollection.updateOne(filter, update);
  

          const payment = {
            amount: session.amount_total / 100,
            currency: session.currency,
            name: session.metadata.userName,
            transactionId: session.payment_intent,
            userEmail:
              session.customer_details?.email || session.metadata.userEmail,
            orderId: orderId,
            paymentStatus: session.payment_status,
            mealName: session.metadata.mealName,
            paidAt: new Date(),
            trackingId: trackingId,
          };

          const paymentResult = await paymentCollections.insertOne(payment);

          await logTracking(trackingId, "order_paid");

          return res.send({
            success: true,
            modifiedCount: updateResult.modifiedCount,
            paymentId: paymentResult.insertedId,
            transactionId: session.payment_intent,
            trackingId: trackingId,
          });
        }
        res.send({ success: false, message: "Payment not paid" });
      } catch (error) {
        console.error("Payment success error:", error);
        res
          .status(500)
          .send({ error: true, message: "Payment confirmation failed" });
      }
    });

    //payment history
    app.get("/payments", verifyFBToken, async (req, res) => {
      const query = {};
      const { email } = req.query;

      if (email) {
        query.userEmail = email;
        // if (email !== req.decoded_email) {
        
          
      }

      const options = {
        sort: { paidAt: -1 },
      };
      const cursor = paymentCollections.find(query, options);
      const result = await cursor.toArray();
      res.send(result);
    });

  
    app.post("/chefs", async (req, res) => {
      const chef = req.body;
      chef.status = "pending";
      chef.createdAt = new Date();

      const result = await chefsCollection.insertOne(chef);
      res.send(result);
    });

    //chef and admin get api

    app.get("/chefs", verifyFBToken, async (req, res) => {
      const { status, workStatus } = req.query;
      const query = {};

      if (status) {
        query.status = status;
      }

      if (workStatus) {
        query.workStatus = workStatus;
      }

      const cursor = chefsCollection.find(query);
      const result = await cursor.toArray();
      res.send(result);
    });


    app.patch("/chefs/:id", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const { status, email } = req.body;

    
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            status: status,
          },
        };

        const result = await chefsCollection.updateOne(filter, updateDoc);

 
        if (status === "approved") {
          const request = await chefsCollection.findOne(filter);

          if (request) {
            const userFilter = { email: request.userEmail };
            const userUpdate = {
              $set: {},
            };
            if (request.requestType === "chef") {
              const chefId = `chef-${Math.floor(1000 + Math.random() * 9000)}`;
              userUpdate.$set.role = "chef";
              userUpdate.$set.chefId = chefId;
            }
           
            else if (request.requestType === "admin") {
              userUpdate.$set.role = "admin";
            }

            await usersCollections.updateOne(userFilter, userUpdate);
          }
        }

        res.send(result);
      } catch (error) {
        console.error("Error updating chef request:", error);
        res
          .status(500)
          .send({ error: true, message: "Failed to update request" });
      }
    });

   
  } finally {
  }
}
run().catch(console.dir);

app.listen(port)