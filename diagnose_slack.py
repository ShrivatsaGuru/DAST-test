#!/usr/bin/env python3
"""
Slack Bot Diagnostic Tool
Tests Slack bot token and permissions
"""

import os
from dotenv import load_dotenv
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

# Load environment variables
load_dotenv()

def test_slack_auth():
    """Test Slack authentication and permissions"""
    
    slack_token = os.getenv('SLACK_BOT_TOKEN')
    slack_channel = os.getenv('SLACK_CHANNEL', '#general')
    
    if not slack_token:
        print("❌ No SLACK_BOT_TOKEN found in environment variables")
        return False
    
    print(f"🔍 Testing Slack bot token...")
    print(f"   Token: {slack_token[:20]}...{slack_token[-10:]}")
    print(f"   Channel: {slack_channel}")
    print()
    
    try:
        client = WebClient(token=slack_token)
        
        # Test 1: Check if token is valid
        print("🧪 Test 1: Checking token validity...")
        auth_response = client.auth_test()
        print(f"✅ Token is valid!")
        print(f"   Bot User: {auth_response['user']}")
        print(f"   Bot ID: {auth_response['user_id']}")
        print(f"   Team: {auth_response['team']}")
        print()
        
        # Test 2: List channels to verify channel exists
        print("🧪 Test 2: Checking available channels...")
        try:
            channels_response = client.conversations_list(types="public_channel,private_channel")
            channels = channels_response['channels']
            
            channel_names = [f"#{ch['name']}" for ch in channels]
            print(f"✅ Found {len(channels)} channels")
            print(f"   Available channels: {', '.join(channel_names[:10])}")
            
            # Check if target channel exists
            target_channel = slack_channel.lstrip('#')
            channel_exists = any(ch['name'] == target_channel for ch in channels)
            
            if channel_exists:
                print(f"✅ Target channel '{slack_channel}' exists")
            else:
                print(f"⚠️  Target channel '{slack_channel}' not found")
                print(f"   Try one of these channels: {', '.join(channel_names[:5])}")
            print()
            
        except SlackApiError as e:
            print(f"⚠️  Cannot list channels: {e.response['error']}")
            print("   This might be due to limited permissions")
            print()
        
        # Test 3: Try to send a simple message
        print("🧪 Test 3: Trying to send a test message...")
        try:
            test_response = client.chat_postMessage(
                channel=slack_channel,
                text="🧪 DAST Integration Test - This is a test message from your DAST security scanner!"
            )
            print(f"✅ Test message sent successfully!")
            print(f"   Message timestamp: {test_response['ts']}")
            return True
            
        except SlackApiError as e:
            error_code = e.response['error']
            print(f"❌ Failed to send message: {error_code}")
            
            if error_code == 'channel_not_found':
                print("   💡 Solution: Make sure the channel exists and the bot is invited to it")
                print(f"   Try: /invite @{auth_response['user']} in the {slack_channel} channel")
            elif error_code == 'not_in_channel':
                print("   💡 Solution: Invite the bot to the channel")
                print(f"   Try: /invite @{auth_response['user']} in the {slack_channel} channel")
            elif error_code == 'missing_scope':
                print("   💡 Solution: Add required permissions to your bot")
                print("   Required scopes: chat:write, chat:write.public")
            else:
                print(f"   💡 Check Slack API documentation for error: {error_code}")
            
            return False
            
    except SlackApiError as e:
        error_code = e.response['error']
        print(f"❌ Authentication failed: {error_code}")
        
        if error_code == 'invalid_auth':
            print("   💡 Possible issues:")
            print("   1. Token might be expired or revoked")
            print("   2. Token might be from a different workspace")
            print("   3. App might be uninstalled from workspace")
            print("   4. Token might be incorrect (copy/paste error)")
        
        return False
    
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        return False

def main():
    """Main diagnostic function"""
    print("🔧 Slack Bot Diagnostic Tool")
    print("=" * 40)
    print()
    
    success = test_slack_auth()
    
    print()
    print("=" * 40)
    if success:
        print("🎉 All tests passed! Your Slack integration is working correctly.")
    else:
        print("❌ There are issues with your Slack integration.")
        print("   Follow the solutions above to fix the problems.")

if __name__ == "__main__":
    main()