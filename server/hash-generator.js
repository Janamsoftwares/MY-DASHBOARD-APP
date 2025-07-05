const bcrypt = require('bcryptjs');

async function generateHash() {
  const password = 'drnet@2030#.';
  const saltRounds = 12;
  
  try {
    const hash = await bcrypt.hash(password, saltRounds);
    console.log('🔐 Password Hash Generated');
    console.log('=========================');
    console.log('Password:', password);
    console.log('Hash:', hash);
    console.log('=========================');
    console.log('Copy this hash to your .env file:');
    console.log(`ADMIN_PASSWORD_HASH=${hash}`);
    return hash;
  } catch (error) {
    console.error('Error generating hash:', error);
  }
}

generateHash();