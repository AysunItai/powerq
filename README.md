# PowerQ - Quadrillian Chat Integration

A professional website showcasing real-time chat functionality powered by [Quadrillian](https://eng.quadrillian.com/).

## Features

- 🎨 Modern, responsive design
- 💬 Real-time chat integration with Quadrillian
- 🔒 Secure JWT-based authentication
- 📱 Mobile-friendly with hamburger menu
- ⚡ Fast and lightweight

## Prerequisites

- Node.js 14+ and npm
- Quadrillian workspace credentials (workspace ID and secret)

## Local Development

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd powerQ
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` and add your Quadrillian credentials:
   ```
   QUAD_WORKSPACE_ID=your_workspace_id
   QUAD_WORKSPACE_SECRET=your_workspace_secret
   QUAD_BASE_URL=https://eng.quadrillian.com
   ```

4. **Start the development server**
   ```bash
   npm run dev
   ```

5. **Open your browser**
   Navigate to `http://localhost:3000`

## Deployment to Render

### Step 1: Push to GitHub

1. Initialize git (if not already done):
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   ```

2. Create a new repository on GitHub and push:
   ```bash
   git remote add origin <your-github-repo-url>
   git branch -M main
   git push -u origin main
   ```

### Step 2: Deploy on Render

1. **Create a new Web Service** on [Render](https://render.com)

2. **Connect your GitHub repository**

3. **Configure the service:**
   - **Name**: powerq (or your preferred name)
   - **Environment**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Plan**: Free or Starter (your choice)

4. **Add Environment Variables** in Render dashboard:
   ```
   QUAD_WORKSPACE_ID=your_workspace_id
   QUAD_WORKSPACE_SECRET=your_workspace_secret
   QUAD_BASE_URL=https://eng.quadrillian.com
   PORT=3000
   FRONTEND_URL=https://your-app-name.onrender.com
   ```

5. **Deploy!** Render will automatically build and deploy your app.

### Important Notes

- ✅ The app is configured to use **https://eng.quadrillian.com** as the production Quadrillian base URL
- ✅ Make sure to set `FRONTEND_URL` to your Render app URL for proper CORS
- ✅ Never commit your `.env` file to GitHub (it's in `.gitignore`)
- ✅ Your Render app will be available at `https://your-app-name.onrender.com`

## Project Structure

```
powerQ/
├── public/
│   └── index.html      # Main website HTML
├── server.js            # Express server with JWT auth
├── package.json         # Dependencies
├── .env.example         # Environment variables template
├── .gitignore          # Git ignore rules
└── README.md           # This file
```

## API Endpoints

- `POST /api/chat/auth` - Generate JWT token for chat authentication
- `GET /api/chat/config` - Get Quadrillian configuration

## Security Notes

⚠️ **Important**: The `/api/chat/auth` endpoint should be protected by your authentication middleware in production. Currently, it uses a demo user for testing purposes.

## Technologies Used

- **Express.js** - Web server
- **Quadrillian** - Chat platform integration
- **JWT** - Authentication tokens
- **Vanilla JavaScript** - Frontend interactions

## License

ISC

## Support

For Quadrillian integration support, visit:
- [Quadrillian Documentation](https://eng.quadrillian.com/)
- [Quadrillian Integration Guide](https://eng.quadrillian.com/docs)

