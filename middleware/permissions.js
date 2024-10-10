// middleware/permissions.js

const { createConnection } = require('../src/cli');

async function canViewLabel(req, res, next) {
    const labelId = req.params.id;
    const shareToken = req.query.token;
    const userId = req.user ? req.user.UserID : null;

    console.log(`canViewLabel middleware called for label ID: ${labelId}`);
    console.log(`User ID: ${userId}`);
    console.log(`Share Token: ${shareToken}`);

    const connection = await createConnection();

    try {
        const [labelRows] = await connection.query('SELECT * FROM Labels WHERE LabelID = ?', [labelId]);
        console.log(`Label Rows: ${JSON.stringify(labelRows)}`);

        if (labelRows.length === 0) {
            console.log('Label not found');
            return res.status(404).send('Label not found');
        }

        const label = labelRows[0];
        req.label = label;
        console.log(`Label Data: ${JSON.stringify(label)}`);

        // Check if the user is the owner
        if (userId && label.UserID === userId) {
            console.log('User is the owner of the label');
            req.canEdit = true;
            return next();
        }

        // Check if the label is public
        if (label.Status === 'public') {
            console.log('Label is public');
            req.canEdit = false;
            return next();
        }

        // Check if a valid share token is provided
        if (shareToken) {
            console.log('Checking share token validity');
            const [shareRows] = await connection.query(
                'SELECT * FROM SharedLabels WHERE LabelID = ? AND ShareToken = ?',
                [labelId, shareToken]
            );
            console.log(`Share Rows: ${JSON.stringify(shareRows)}`);
            if (shareRows.length > 0) {
                console.log('Valid share token provided');
                req.canEdit = false;
                return next();
            } else {
                console.log('Invalid share token');
            }
        }

        // User does not have permission
        console.log('User does not have permission to view this label');
        return res.status(403).send('You do not have permission to view this label.');
    } catch (error) {
        console.error('Error in permission middleware:', error);
        res.status(500).send('Internal server error');
    } finally {
        connection.end();
    }
}

module.exports = {
    canViewLabel
};
