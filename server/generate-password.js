const bcrypt = require('bcryptjs');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

async function generatePasswordHash() {
  console.log('🔐 Dr.Net Admin Password Hash Generator');
  console.log('=====================================\n');
  
  rl.question('Enter your desired admin password: ', async (password) => {
    if (password.length < 8) {
      console.log('❌ Password must be at least 8 characters long!');
      rl.close();
      return;
    }

    try {
      console.log('\n⏳ Generating secure hash...');
      const saltRounds = 12;
      const hash = await bcrypt.hash(password, saltRounds);
      
      console.log('\n✅ Password hash generated successfully!');
      console.log('=====================================');
      console.log('Add this to your .env file:');
      console.log(`ADMIN_PASSWORD_HASH=${hash}`);
      console.log('=====================================\n');
      console.log('🔒 Your login credentials will be:');
      console.log(`Username: admin`);
      console.log(`Password: ${password}`);
      console.log('\n⚠️  Keep this password secure and don\'t share it!');
      
    } catch (error) {
      console.error('❌ Error generating hash:', error);
    }
    
    rl.close();
  });
}

generatePasswordHash();