# MoveOut Project

MoveOut is a web-based platform designed to help users organize and manage their moving process by creating customizable labels for moving boxes. The platform provides features such as label creation with text, image, or audio content, secure label sharing via QR codes, and specialized insurance labels.

## Table of Contents
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Installation](#installation)
- [Usage](#usage)
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

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/moveout.git
   cd moveout
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Configure Environment Variables**:
   Create a `.env` file in the root directory and add the following:
   ```
   DB_HOST=your_database_host
   DB_USER=your_database_user
   DB_PASSWORD=your_database_password
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   SESSION_SECRET=your_session_secret
   ```

4. **Run the Application**:
   ```bash
   npm start
   ```

5. **Access the App**:
   Visit `http://localhost:3000` in your browser.

## Usage

- **Register/Login**: Create an account using your email or Google.
- **Create Labels**: Use the "Create Label" feature to generate box labels with text, images, or audio.
- **Scan QR Codes**: View label details by scanning QR codes with a compatible device.
- **Share Labels**: Share labels securely by generating a PIN for access.
- **Profile Managment**: Manage your profile change passowrd, change porfile picture and deactivate your account.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
