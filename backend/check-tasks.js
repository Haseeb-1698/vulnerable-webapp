const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function checkTasks() {
  try {
    console.log('🔍 Checking existing tasks...');
    
    const tasks = await prisma.task.findMany({
      include: {
        user: {
          select: { firstName: true, lastName: true, email: true }
        }
      }
    });
    
    console.log(`📋 Found ${tasks.length} tasks:`);
    tasks.forEach(task => {
      console.log(`  - Task ${task.id}: "${task.title}" (Owner: ${task.user.email})`);
    });
    
    if (tasks.length === 0) {
      console.log('⚠️  No tasks found. Creating a test task...');
      
      // Find first user
      const user = await prisma.user.findFirst();
      if (user) {
        const newTask = await prisma.task.create({
          data: {
            userId: user.id,
            title: 'XSS Testing Task',
            description: 'A task for testing XSS vulnerabilities',
            priority: 'MEDIUM',
            status: 'TODO'
          }
        });
        console.log(`✅ Created task ${newTask.id} for XSS testing`);
      } else {
        console.log('❌ No users found. Please create a user first.');
      }
    }
    
  } catch (error) {
    console.error('❌ Error:', error.message);
  } finally {
    await prisma.$disconnect();
  }
}

checkTasks();