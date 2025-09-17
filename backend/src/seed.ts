import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting database seed...');

  // Create demo users (use upsert to handle existing data)
  const hashedPassword = await bcrypt.hash('password123', 10);

  const user1 = await prisma.user.upsert({
    where: { email: 'alice@example.com' },
    update: {},
    create: {
      email: 'alice@example.com',
      passwordHash: hashedPassword,
      firstName: 'Alice',
      lastName: 'Johnson',
      emailVerified: true,
    },
  });

  const user2 = await prisma.user.upsert({
    where: { email: 'bob@example.com' },
    update: {},
    create: {
      email: 'bob@example.com',
      passwordHash: hashedPassword,
      firstName: 'Bob',
      lastName: 'Smith',
      emailVerified: true,
    },
  });

  const user3 = await prisma.user.upsert({
    where: { email: 'charlie@example.com' },
    update: {},
    create: {
      email: 'charlie@example.com',
      passwordHash: hashedPassword,
      firstName: 'Charlie',
      lastName: 'Brown',
      emailVerified: true,
    },
  });

  console.log('✅ Created/updated demo users');

  // Create demo tasks for user1
  const task1 = await prisma.task.create({
    data: {
      userId: user1.id,
      title: 'Complete project documentation',
      description: 'Write comprehensive documentation for the security learning project',
      priority: 'HIGH',
      status: 'IN_PROGRESS',
      dueDate: new Date('2024-12-31'),
    },
  });

  const task2 = await prisma.task.create({
    data: {
      userId: user1.id,
      title: 'Review security vulnerabilities',
      description: 'Analyze and document all intentional security vulnerabilities',
      priority: 'URGENT',
      status: 'TODO',
      dueDate: new Date('2024-11-15'),
    },
  });

  // Create demo tasks for user2
  const task3 = await prisma.task.create({
    data: {
      userId: user2.id,
      title: 'Set up development environment',
      description: 'Configure Docker containers and database connections',
      priority: 'MEDIUM',
      status: 'COMPLETED',
    },
  });

  const task4 = await prisma.task.create({
    data: {
      userId: user2.id,
      title: 'Implement authentication system',
      description: 'Build JWT-based authentication with intentional vulnerabilities',
      priority: 'HIGH',
      status: 'IN_PROGRESS',
    },
  });

  // Create demo tasks for user3
  await prisma.task.create({
    data: {
      userId: user3.id,
      title: 'Test SQL injection vulnerabilities',
      description: 'Verify that SQL injection attacks work as expected',
      priority: 'LOW',
      status: 'TODO',
    },
  });

  console.log('✅ Created demo tasks');

  // Create demo comments
  await prisma.comment.create({
    data: {
      taskId: task1.id,
      userId: user2.id,
      content: 'Great progress on the documentation! Make sure to include security warnings.',
    },
  });

  await prisma.comment.create({
    data: {
      taskId: task1.id,
      userId: user3.id,
      content: 'Should we add examples of each vulnerability type?',
    },
  });

  await prisma.comment.create({
    data: {
      taskId: task2.id,
      userId: user1.id,
      content: 'This is a critical task for the educational value of the project.',
    },
  });

  await prisma.comment.create({
    data: {
      taskId: task3.id,
      userId: user1.id,
      content: 'Excellent work on the Docker setup! Everything is working smoothly.',
    },
  });

  // Create a comment with potential XSS payload for testing
  await prisma.comment.create({
    data: {
      taskId: task4.id,
      userId: user3.id,
      content: '<script>console.log("This will be vulnerable to XSS")</script>Authentication looks good so far!',
    },
  });

  console.log('✅ Created demo comments');
  console.log('🎉 Database seed completed successfully!');
  console.log('\n📋 Demo Users:');
  console.log('  - alice@example.com (password: password123)');
  console.log('  - bob@example.com (password: password123)');
  console.log('  - charlie@example.com (password: password123)');
}

main()
  .catch((e) => {
    console.error('❌ Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });