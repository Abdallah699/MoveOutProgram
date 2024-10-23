# MoveOut Project

MoveOut is a web-based platform designed to help users organize and manage their moving process by creating customizable labels for moving boxes. The platform provides features such as label creation with text, image, or audio content, secure label sharing via QR codes, and specialized insurance labels.

## Table of Contents
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Installation](#installation)
- [Usage](#usage)
- [ER Diagram](#er-diagram)
- [License](#license)

## Features
- **User Registration**: Secure user registration with email verification or Google OAuth integration.
- **Label Creation**: Create labels with text, image, or audio content to describe the contents of moving boxes.
- **QR Codes**: Each label has an associated QR code, allowing users to quickly view details by scanning.
- **Secure Label Sharing**: Share labels with others securely using a PIN-based access system.
- **Insurance Labels**: Create specialized labels for insured items, listing item details and values in various currencies.
- **Account Management**: Update or deactivate user profiles, with inactive profiles being automatically deactivated after a month.

## Technologies Used
- **Frontend**:
  - EJS: Dynamic HTML rendering.
  - CSS: Styling for the user interface.
- **Backend**:
  - Node.js & Express: Server-side logic and routing.
  - SQL (MySQL): Database for managing users, labels, and content.
- **Additional Tools**:
  - **QR Code Generation**: Makes labels scannable for easy access.
  - **Security**: Password hashing, PIN-based sharing.
  - **Version Control**: Git for version control and collaboration.

## Installation

To run the MoveOut project locally, follow these steps:

1. **Install Node.js and npm**:
   
   First, you need to install Node.js and npm (Node Package Manager). Follow the instructions below for your operating system:

   - **Windows**:
     1. Visit the [Node.js download page](https://nodejs.org/).
     2. Download the Windows installer and follow the installation steps.
     3. Verify the installation by running the following commands in Command Prompt:
        ```bash
        node -v
        npm -v
        ```

   - **macOS**:
     1. Install [Homebrew](https://brew.sh/) if you don't have it:
        ```bash
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        ```
     2. Use Homebrew to install Node.js:
        ```bash
        brew install node
        ```
     3. Verify the installation by running:
        ```bash
        node -v
        npm -v
        ```

   - **Linux**:
     1. Update your package list and install Node.js:
        ```bash
        sudo apt update
        sudo apt install nodejs npm
        ```
     2. Verify the installation by running:
        ```bash
        node -v
        npm -v
        ```

2. **Clone the repository**:
   
   Clone the MoveOut repository to your local machine:
   ```bash
   git clone https://github.com/yourusername/moveout.git
   cd moveout
   ```

3. **Install dependencies**:
   
   Install the required Node.js dependencies:
   ```bash
   npm install
   ```

4. **Configure Environment Variables**:
   
   Create a `.env` file in the root directory and add the following:
   ```
   DB_HOST=your_database_host
   DB_USER=your_database_user
   DB_PASSWORD=your_database_password
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   SESSION_SECRET=your_session_secret
   ```

5. **Run the Application**:
   
   Start the server by running:
   ```bash
   npm start
   ```

6. **Access the App**:
   
   Open your browser and visit `http://localhost:3000` to use the application.

## Usage

- **Register/Login**: Create an account using your email or Google.
- **Create Labels**: Use the "Create Label" feature to generate box labels with text, images, or audio.
- **Scan QR Codes**: View label details by scanning QR codes with a compatible device.
- **Share Labels**: Share labels securely by generating a PIN for access.

## ER Diagram

Below is the ER diagram that represents the database schema for the MoveOut project:

![ER Diagram](./public/images/ERDiagram.png)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
